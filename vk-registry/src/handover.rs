//! Handing the registry from one process to the next when its hub updates it, so that no
//! connection is refused and, under systemd, none open is cut: not even a blob upload or
//! download hours long.
//!
//! [`hand_over`] transfers the build-once lock table and pending logins through an inherited
//! memory file, never disk: they contain owner tokens and PKCE verifiers. It closes the
//! accounts db for the release to open. The caller transfers the hub link: its session
//! closes, and only the release saves its state from then on. These resources have one
//! owner at a time; the store needs no hand-over because it supports concurrent processes.
//! [`vk_peer::handoff`] transfers both the registry and accounts admin listening sockets.
//!
//! Two shapes, by what the registry runs under ([`Shape`]):
//!
//! - **Overlap**, under a service manager that listens (`$NOTIFY_SOCKET`, which the units
//!   `install-service` writes ask for with `NotifyAccess=main`). The registry stops accepting
//!   and hands over, then starts the release beside itself, which takes over in two steps: it
//!   takes the sockets and opens what it was handed, says so ([`Taken::prepared`]), and serves
//!   only once told to. A release that does not get as far is ended, and the registry takes
//!   everything back and serves on. Once the release serves, this process finishes the
//!   requests it has open — the transfers under way — for at most `[hub]
//!   update_drain_minutes`, still the unit's main process so the manager keeps watching it;
//!   then it names the release the main process (`MAINPID=`, [`vk_peer::notify`]) and exits. A
//!   release that ends meanwhile ends it too, with a failure, for the manager to start the
//!   registry again: the previous binary, which counts the release's attempts as for any trial.
//! - **Exec**, otherwise: the registry stops accepting, gives the requests open a few seconds
//!   ([`GRACE`]), hands over and executes the release in its place, with the sockets. No
//!   connection is refused; those still open are cut.
//!
//! A release from before this hand-over is executed as before, handed nothing.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use vk_peer::handoff::{Gate, Inherited, Passing};
use vk_peer::update::Binary;

use crate::{Authenticator, ServerState, lock};

/// The registry's listening socket, as [`vk_peer::handoff`] names it.
pub const SOCKET: &str = "registry";

/// The accounts admin socket, as [`vk_peer::handoff`] names it.
pub const ADMIN_SOCKET: &str = "admin";

/// The variable naming the memory file [`Carried`] is read from.
const CARRIED_ENV: &str = "VK_REGISTRY_CARRIED_FD";

/// The variable naming the pipe an overlapping release says it is prepared on.
const READY_ENV: &str = "VK_REGISTRY_READY_FD";

/// The variable naming the pipe an overlapping release is told to serve on.
const GO_ENV: &str = "VK_REGISTRY_GO_FD";

/// [`Carried`]'s format, which a release reads only if it knows it.
const FORMAT: u32 = 1;

/// The most [`Carried`] a release reads, and a registry hands over: a lock table of 10,000
/// failure records of at most 4 KiB, escaped, plus its leases and the logins under way, fits.
const MAX_CARRIED: u64 = 256 << 20;

/// How long the requests open have to end before the registry executes its release.
pub const GRACE: Duration = Duration::from_secs(5);

/// How long an overlapping release has to say it is prepared.
const PREPARE_WAIT: Duration = Duration::from_secs(60);

/// How long the service manager has to read that the release is the main process.
const NOTIFY_WAIT: Duration = Duration::from_secs(10);

/// What says a release takes part in an overlap and reads [`Carried`] in this [`FORMAT`]: one
/// without it is never started beside the registry, which would fail the update, but
/// executed in its place. Ends with [`FORMAT`], as a test checks.
const OVERLAP_MARKER: &[u8] = b"vk-registry-overlap-format-1";

/// The listeners a registry serves through, to hand over: one per process.
#[derive(Default)]
pub struct Handover {
    pub gate: Gate,
    pub passing: Passing,
}

/// What one process hands the next. No `Debug`, for the owner tokens and PKCE verifiers.
#[derive(Serialize, Deserialize)]
pub struct Carried {
    format: u32,
    /// When it was handed over, Unix milliseconds: the time it spent in between is off its
    /// leases and logins.
    at_ms: u64,
    locks: lock::Snapshot,
    logins: Vec<Login>,
}

/// A login under way ([`vk_oidc::Pending`]).
#[derive(Serialize, Deserialize)]
struct Login {
    state: String,
    target: String,
    verifier: String,
    left_ms: u64,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Carried {
    /// Take on what was carried: the lock table in place of `state`'s, the logins under way.
    pub fn restore(self, state: &mut ServerState) {
        let since = Duration::from_millis(unix_ms().saturating_sub(self.at_ms));
        state.locks = lock::LockManager::restore(self.locks, since);
        restore_logins(state, self.logins, since);
    }
}

/// Have `state`'s OIDC client finish `logins`, handed over `since` ago.
/// Called even with none: restoring is what lets the client start logins again.
fn restore_logins(state: &ServerState, logins: Vec<Login>, since: Duration) {
    if let Authenticator::Accounts { oidc, .. } = &state.auth {
        let handed = logins.len();
        let taken = oidc.restore_pending(
            logins
                .into_iter()
                .map(|l| vk_oidc::Pending {
                    state: l.state,
                    target: l.target,
                    verifier: l.verifier,
                    left: Duration::from_millis(l.left_ms).saturating_sub(since),
                })
                .collect(),
        );
        if handed > 0 {
            eprintln!(
                "vk-registry: finishing {taken} of the {handed} sign-in(s) under way handed over"
            );
        }
    }
}

/// What a release was handed as it started, until taken.
#[derive(Default)]
pub struct Taken {
    pub sockets: Inherited,
    pub carried: Option<Carried>,
    /// Why what was carried could not be read, when it could not.
    pub unread: Option<String>,
    /// An overlapping release's pipes: it says it is prepared on the first, and is told to
    /// serve on the second, whose end it then sees once the registry has left.
    pipes: Option<(std::fs::File, std::fs::File)>,
    /// Whether the environment names an overlap's pipes, taken or not: a release started
    /// beside the registry that cannot take them must not serve.
    pipes_named: bool,
    /// What was wrong, for the log.
    pub problems: Vec<String>,
    /// The descriptors taken, each once.
    seen: Vec<RawFd>,
}

/// Whether [`Taken::from_env`] has run: the descriptors are owned once.
static TAKEN: AtomicBool = AtomicBool::new(false);

/// Set while this release serves beside the registry it updated, which is still the service
/// manager's main process: it takes no update of its own until that one has left.
static OVERLAPPED: AtomicBool = AtomicBool::new(false);

/// Whether this process still serves beside the registry it updated ([`OVERLAPPED`]).
pub fn overlapped() -> bool {
    OVERLAPPED.load(Ordering::SeqCst)
}

impl Taken {
    /// What the environment names; the first call only, later ones take nothing.
    pub fn from_env() -> Self {
        if TAKEN.swap(true, Ordering::SeqCst) {
            return Taken::default();
        }
        let sockets = Inherited::from_env();
        let mut taken = Taken {
            problems: sockets.problems.clone(),
            sockets,
            ..Taken::default()
        };
        let named = |env: &str| std::env::var_os(env).is_some_and(|v| !v.is_empty());
        if let Some(fd) = taken.fd(CARRIED_ENV, libc::S_IFREG)
            && taken.sealed(CARRIED_ENV, &fd)
        {
            match read_carried(&std::fs::File::from(fd)) {
                Ok(c) => taken.carried = Some(c),
                Err(e) => taken.unread = Some(format!("{CARRIED_ENV}: {e:#}")),
            }
        } else if named(CARRIED_ENV) {
            taken.unread = Some(format!("{CARRIED_ENV}: the descriptor named is not taken"));
        }
        taken.pipes_named = named(READY_ENV) || named(GO_ENV);
        match (
            taken.fd(READY_ENV, libc::S_IFIFO),
            taken.fd(GO_ENV, libc::S_IFIFO),
        ) {
            (Some(ready), Some(go)) => taken.pipes = Some((ready.into(), go.into())),
            (None, None) => {}
            _ => taken.problems.push(format!(
                "{READY_ENV} and {GO_ENV} go together; neither is used"
            )),
        }
        taken
    }

    /// Take the descriptor named by `env` and make it close-on-exec. It must be open,
    /// inherited (not close-on-exec, unlike descriptors opened since), not named before,
    /// and of type `kind`, which excludes inherited listening sockets.
    fn fd(&mut self, env: &str, kind: libc::mode_t) -> Option<OwnedFd> {
        let value = std::env::var(env).ok().filter(|v| !v.is_empty())?;
        let fd = match value.parse::<RawFd>() {
            Ok(fd) if fd > 2 && !self.seen.contains(&fd) => fd,
            _ => {
                self.problems
                    .push(format!("{env}={value:?} is not a descriptor of its own"));
                return None;
            }
        };
        // SAFETY: F_GETFD reads a descriptor's flags and touches no memory.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let inherited = flags >= 0 && flags & libc::FD_CLOEXEC == 0;
        // SAFETY: a zeroed stat is a valid value for fstat to overwrite.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat writes only into `st`; a descriptor not open fails.
        if !inherited
            || unsafe { libc::fstat(fd, &mut st) } != 0
            || st.st_mode & libc::S_IFMT != kind
        {
            self.problems.push(format!(
                "{env}: descriptor {fd} is not open, not inherited, or not what it should be"
            ));
            return None;
        }
        self.seen.push(fd);
        // SAFETY: open, of a type no socket taken is, named once, and taken once: `from_env`
        // runs once.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Not passed on to a child of this release.
        if let Err(e) = set_cloexec(fd.as_raw_fd(), true) {
            self.problems
                .push(format!("{env}: descriptor {fd:?} stays inheritable: {e}"));
        }
        Some(fd)
    }

    /// Whether `fd`, which `env` names, is a memory file sealed against writes, as [`carry`]
    /// leaves one: not a file a number left in the environment could name otherwise.
    fn sealed(&mut self, env: &str, fd: &OwnedFd) -> bool {
        // SAFETY: F_GET_SEALS reads a descriptor's seals and touches no memory; it fails on
        // anything but a memory file.
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        let sealed = seals >= 0 && seals & libc::F_SEAL_WRITE != 0;
        if !sealed {
            self.problems.push(format!(
                "{env}: descriptor {fd:?} is not a sealed memory file"
            ));
        }
        sealed
    }

    /// Whether this release was started beside the registry it updates, to serve once told.
    pub fn overlapping(&self) -> bool {
        self.pipes_named
    }

    /// An overlapping release reports that it has taken the sockets and opened the handed
    /// state, then waits for permission to serve. On `Err`, the registry serves on and this
    /// release must exit without serving. After permission, updates stay blocked
    /// ([`overlapped`]) until the registry exits. Other releases return immediately.
    pub fn prepared(&mut self) -> Result<()> {
        let Some((mut ready, mut go)) = self.pipes.take() else {
            if self.pipes_named {
                bail!("{READY_ENV} and {GO_ENV} are named, and not both taken");
            }
            return Ok(());
        };
        ready
            .write_all(b"p")
            .context("telling the registry this release is prepared")?;
        drop(ready);
        let mut byte = [0u8; 1];
        match go.read(&mut byte) {
            Ok(1) if byte == *b"g" => {}
            Ok(_) => bail!("the registry did not hand over"),
            Err(e) => return Err(e).context("waiting for the registry to hand over"),
        }
        OVERLAPPED.store(true, Ordering::SeqCst);
        std::thread::spawn(move || {
            // The registry holds its end until it exits.
            let mut rest = Vec::new();
            let _ = go.read_to_end(&mut rest);
            OVERLAPPED.store(false, Ordering::SeqCst);
        });
        Ok(())
    }
}

/// [`Carried`] as `file` holds it, read from its start: whatever read it before, through the
/// same open file, leaves no offset behind.
fn read_carried(file: &std::fs::File) -> Result<Carried> {
    let mut bytes = Vec::new();
    std::io::Seek::rewind(&mut &*file).context("reading it")?;
    file.take(MAX_CARRIED + 1)
        .read_to_end(&mut bytes)
        .context("reading it")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CARRIED {
        bail!("it is larger than {MAX_CARRIED} bytes");
    }
    #[derive(Deserialize)]
    struct Format {
        format: u32,
    }
    let format: Format = serde_json::from_slice(&bytes).context("parsing it")?;
    if format.format != FORMAT {
        bail!(
            "it is in format {}, and this release reads {FORMAT}",
            format.format
        );
    }
    serde_json::from_slice(&bytes).context("parsing it")
}

/// How the registry hands over to a release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Started beside it: the transfers open finish here.
    Overlap,
    /// Executed in its place, with its sockets.
    Exec,
    /// Executed in its place, handed nothing: a release from before the hand-over.
    Plain,
}

impl Shape {
    /// The shape for `release`: by what it takes part in, and whether a service manager can
    /// be told it is the main process.
    pub fn of(release: &std::fs::File) -> Result<Shape> {
        let (overlap, handoff) = markers(release)?;
        Ok(Shape::from(overlap, handoff, vk_peer::notify::available()))
    }

    fn from(overlap: bool, handoff: bool, manager: bool) -> Shape {
        match (overlap, handoff) {
            (true, _) if manager => Shape::Overlap,
            (true, _) | (false, true) => Shape::Exec,
            (false, false) => Shape::Plain,
        }
    }
}

/// Whether `release` names [`OVERLAP_MARKER`], and [`vk_peer::handoff::ENV`]: whether it takes
/// part in an overlap, and takes sockets handed over. Every vk-registry that names the latter reads
/// [`Carried`] too: the two came in one release.
fn markers(release: &std::fs::File) -> Result<(bool, bool)> {
    use std::os::unix::fs::FileExt;
    let handoff = vk_peer::handoff::ENV.as_bytes();
    // A marker split across two reads is found in the tail kept from the first.
    let tail = OVERLAP_MARKER.len().max(handoff.len()) - 1;
    let (mut overlap, mut takes) = (false, false);
    let mut buf = vec![0u8; 1 << 20];
    let (mut kept, mut offset) = (0, 0u64);
    loop {
        let n = release
            .read_at(&mut buf[kept..], offset)
            .context("reading the release")?;
        if n == 0 {
            return Ok((overlap, takes));
        }
        offset += u64::try_from(n).unwrap_or(u64::MAX);
        let window = &buf[..kept + n];
        overlap |= window
            .windows(OVERLAP_MARKER.len())
            .any(|w| w == OVERLAP_MARKER);
        takes |= window.windows(handoff.len()).any(|w| w == handoff);
        if overlap && takes {
            return Ok((true, true));
        }
        kept = tail.min(window.len());
        let start = window.len() - kept;
        buf.copy_within(start..start + kept, 0);
    }
}

/// What the registry handed over: the memory file the release reads it from, and the logins
/// under way, to take back should the release not take over. The lock table is kept here,
/// unchanged, all along.
pub struct Handed {
    file: std::fs::File,
    logins: Vec<Login>,
    /// When it was handed over: the logins taken back lose what passed since.
    at: std::time::Instant,
}

/// Stop accepting and hand over what only one process may hold: the lock table, the logins
/// under way, the accounts db. The hub link is the caller's. On failure everything is taken
/// back. Blocking: the accounts db's last write is synced.
pub fn hand_over(state: &ServerState) -> Result<Handed> {
    let (at, at_ms) = (std::time::Instant::now(), unix_ms());
    state.handover.gate.close();
    let locks = state.locks.hand_over();
    let mut logins = Vec::new();
    if let Authenticator::Accounts { db, oidc } = &state.auth {
        logins = oidc
            .take_pending()
            .into_iter()
            .map(|p| Login {
                state: p.state,
                target: p.target,
                verifier: p.verifier,
                left_ms: u64::try_from(p.left.as_millis()).unwrap_or(u64::MAX),
            })
            .collect();
        if let Err(e) = db.hand_over() {
            restore_logins(state, logins, at.elapsed());
            state.locks.take_back();
            state.handover.gate.open();
            return Err(e.context("closing the accounts db for the release"));
        }
    }
    let carried = Carried {
        format: FORMAT,
        at_ms,
        locks,
        logins,
    };
    match carry(&carried) {
        Ok(file) => Ok(Handed {
            file,
            logins: carried.logins,
            at,
        }),
        Err(e) => {
            take_back(state, carried.logins, at);
            Err(e)
        }
    }
}

/// How often, and how far apart, the accounts db is opened again before the registry gives up
/// and ends, for its supervisor to start it afresh.
const REOPEN_TRIES: u32 = 5;
const REOPEN_EVERY: Duration = Duration::from_secs(1);

/// Take back what [`hand_over`] handed `at`, with the `logins` under way, and accept again. An
/// accounts db that cannot be opened again ends the registry, with a failure, there and then:
/// serving on without it would refuse every credential. The trial stays recorded, so the
/// supervisor's next start retries the release ([`crate::hub::on_start`]). Blocking.
fn take_back(state: &ServerState, logins: Vec<Login>, at: std::time::Instant) {
    if let Authenticator::Accounts { db, .. } = &state.auth {
        let mut tries = 0;
        while let Err(e) = db.take_back() {
            tries += 1;
            if tries >= REOPEN_TRIES {
                eprintln!(
                    "vk-registry: hub: the accounts db cannot be opened again: {e:#}; ending, for \
                     the supervisor to start the registry afresh"
                );
                std::process::exit(1);
            }
            std::thread::sleep(REOPEN_EVERY);
        }
    }
    restore_logins(state, logins, at.elapsed());
    state.locks.take_back();
    state.handover.gate.open();
}

/// [`take_back`] what was `handed`, off the runtime.
async fn take_back_handed(state: &Arc<ServerState>, handed: Handed) {
    let state = state.clone();
    let Handed { logins, at, .. } = handed;
    // A panic in there leaves nothing more to take back.
    if let Err(e) = tokio::task::spawn_blocking(move || take_back(&state, logins, at)).await {
        eprintln!("vk-registry: hub: taking the registry back: {e}");
    }
}

/// `carried`, in a sealed memory file the release reads, close-on-exec until handed.
fn carry(carried: &Carried) -> Result<std::fs::File> {
    let bytes = serde_json::to_vec(carried).context("encoding what is handed over")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CARRIED {
        bail!(
            "what is handed over takes {} bytes, more than a release reads",
            bytes.len()
        );
    }
    // SAFETY: memfd_create takes a NUL-terminated name and returns a new descriptor.
    let raw = unsafe {
        libc::memfd_create(
            c"vk-registry-handover".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("creating a memory file");
    }
    // SAFETY: just created, owned by nothing else.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    file.write_all(&bytes)
        .context("writing what is handed over")?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: F_ADD_SEALS sets a memory file's seals and touches no memory.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error()).context("sealing the memory file");
    }
    Ok(file)
}

/// The environment naming what a release is handed: each variable set, empty for what it is
/// not handed, so none names a descriptor it does not have.
fn fd_env(carried: Option<RawFd>, pipes: Option<(RawFd, RawFd)>) -> Vec<(OsString, OsString)> {
    let named = |fd: Option<RawFd>| fd.map_or_else(OsString::new, |fd| fd.to_string().into());
    vec![
        (CARRIED_ENV.into(), named(carried)),
        (READY_ENV.into(), named(pipes.map(|p| p.0))),
        (GO_ENV.into(), named(pipes.map(|p| p.1))),
    ]
}

/// Execute `binary` in place of the registry, handed nothing: [`Shape::Plain`]. Returns only
/// on failure.
pub fn exec_plain(binary: &Binary, deadline: u64) -> anyhow::Error {
    vk_peer::update::exec_with(binary, Some(deadline), &fd_env(None, None))
}

/// Before an [`exec`]: stop accepting and give the requests open [`GRACE`] to end, while this
/// process still holds what they need.
pub async fn drain(state: &ServerState) {
    state.handover.gate.close();
    if !state.handover.gate.drained(GRACE).await {
        eprintln!(
            "vk-registry: hub: {} connections still open after {GRACE:?} are cut",
            state.handover.gate.live()
        );
    }
}

/// Execute `binary` in place of the registry with its sockets and what it `handed`:
/// [`Shape::Exec`], after [`drain`]. Returns only on failure, having taken everything back.
pub async fn exec(
    state: &Arc<ServerState>,
    binary: &Binary,
    deadline: u64,
    handed: Handed,
) -> anyhow::Error {
    let carried = handed.file.as_raw_fd();
    let e = match state.handover.passing.prepare() {
        Ok(prepared) => match set_cloexec(carried, false) {
            Ok(()) => {
                let mut env = fd_env(Some(carried), None);
                env.push(prepared.env());
                let e = vk_peer::update::exec_with(binary, Some(deadline), &env);
                // The file is dropped with `handed` below, so one left inheritable reaches no
                // child.
                if let Err(e) = set_cloexec(carried, true) {
                    eprintln!("vk-registry: hub: {e}");
                }
                e
            }
            Err(e) => anyhow!(e).context("handing the lock table over"),
        },
        Err(e) => e,
    };
    take_back_handed(state, handed).await;
    e
}

/// Start `binary` beside the registry with its sockets and what it `handed`, and hand over to
/// it once it is prepared: [`Shape::Overlap`]. Then finish the requests open, for at most
/// `drain`, name the release the unit's main process and exit; or exit with a failure if the
/// release ends first. Returns only when the release did not take over, having taken
/// everything back.
pub async fn overlap(
    state: &Arc<ServerState>,
    binary: &Binary,
    deadline: u64,
    handed: Handed,
    drain: Duration,
) -> anyhow::Error {
    let Started {
        mut child,
        ready,
        mut go,
    } = match start(state, binary, deadline, &handed.file) {
        Ok(started) => started,
        Err(e) => {
            take_back_handed(state, handed).await;
            return e;
        }
    };
    let prepared =
        match tokio::task::spawn_blocking(move || wait_prepared(&ready, PREPARE_WAIT)).await {
            Ok(r) => r,
            Err(e) => Err(anyhow!("waiting for the release: {e}")),
        };
    if let Err(e) =
        prepared.and_then(|()| go.write_all(b"g").context("telling the release to serve"))
    {
        // Killed and reaped off the runtime: the child is not reaped before the kill, so its
        // pid is not another process's.
        let reaped = tokio::task::spawn_blocking(move || {
            // An error is a child that has already exited, and is reaped below all the same.
            let _ = child.kill();
            child.wait()
        })
        .await;
        if !matches!(reaped, Ok(Ok(_))) {
            eprintln!("vk-registry: hub: the release that did not take over was not reaped");
        }
        take_back_handed(state, handed).await;
        return e.context("the release did not take over");
    }
    drop(handed);
    let pid = child.id();
    // Never reaped here: should the release end, its exit stays for the service manager to
    // see once this process has left, as the manager watches the main process it was named.
    drop(child);
    eprintln!(
        "vk-registry: hub: the release (pid {pid}) serves; finishing the {} connections open \
         here, for at most {} minutes",
        state.handover.gate.live(),
        drain.as_secs() / 60
    );
    let (ended_tx, ended_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        exited(pid);
        // The receiver is gone only once this process is exiting.
        let _ = ended_tx.send(());
    });
    tokio::pin!(ended_rx);
    tokio::select! {
        _ = &mut ended_rx => release_ended(),
        drained = state.handover.gate.drained(drain) => {
            if !drained {
                eprintln!(
                    "vk-registry: hub: {} connections still open after {} minutes are cut",
                    state.handover.gate.live(),
                    drain.as_secs() / 60
                );
            }
        }
    }
    let told = tokio::task::spawn_blocking(move || {
        vk_peer::notify::notify(&format!("MAINPID={pid}"))
            .and_then(|()| vk_peer::notify::barrier(NOTIFY_WAIT))
    })
    .await
    .unwrap_or_else(|e| Err(anyhow!("telling the service manager: {e}")));
    // A release that ended before the manager read its pid was not taken for the main process.
    if has_exited(pid) {
        release_ended();
    }
    match told {
        Ok(()) => {
            eprintln!("vk-registry: hub: handed over to the release (pid {pid})");
            // The release sees its pipe close as this process exits: it is the main process
            // now, and may take an update of its own.
            drop(go);
            std::process::exit(0);
        }
        Err(e) => {
            // Exiting now could have the manager end the unit, the release with it: stay its
            // main process, idle, for as long as the release serves, which takes no update of
            // its own meanwhile.
            eprintln!(
                "vk-registry: hub: the service manager could not be told the release (pid \
                 {pid}) is the main process: {e:#}; staying until it ends, and the release takes \
                 no update until then"
            );
            // The sender is dropped only once it has sent.
            let _ = ended_rx.await;
            release_ended()
        }
    }
}

/// Child `pid` as `waitid(2)` takes it.
fn child_id(pid: u32) -> libc::id_t {
    libc::id_t::from(pid)
}

/// Whether child `pid` has exited, leaving it unreaped.
fn has_exited(pid: u32) -> bool {
    // SAFETY: a zeroed siginfo_t is valid for waitid to fill; its pid stays 0 while the child
    // runs.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: looks at this process's own child; WNOWAIT leaves it to be reaped.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            child_id(pid),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // SAFETY: waitid filled the siginfo of a child that exited, if any.
    rc == 0 && unsafe { info.si_pid() } != 0
}

/// Wait until child `pid` has exited, leaving it unreaped. A failure other than an interrupt —
/// no such child — is taken for an exit, and logged.
fn exited(pid: u32) {
    loop {
        // SAFETY: a zeroed siginfo_t is valid for waitid to fill.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waits on this process's own child; WNOWAIT leaves it to be reaped.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child_id(pid),
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            eprintln!("vk-registry: hub: waiting for the release (pid {pid}): {e}");
            return;
        }
    }
}

/// The release this process overlapped ended: end too, with a failure, there and then, for the
/// service manager to start the registry again; the trial stays recorded, and that start
/// counts the release's attempt ([`crate::hub::on_start`]).
fn release_ended() -> ! {
    eprintln!("vk-registry: hub: the release ended; ending too");
    std::process::exit(1)
}

/// An overlapping release, started, with this end of each of its pipes.
struct Started {
    child: std::process::Child,
    ready: std::fs::File,
    go: std::fs::File,
}

fn start(
    state: &ServerState,
    binary: &Binary,
    deadline: u64,
    carried: &std::fs::File,
) -> Result<Started> {
    let (ready, ready_child) = pipe()?;
    let (go_child, go) = pipe()?;
    let prepared = state.handover.passing.prepare()?;
    let fds = (
        carried.as_raw_fd(),
        ready_child.as_raw_fd(),
        go_child.as_raw_fd(),
    );
    let mut env = fd_env(Some(fds.0), Some((fds.1, fds.2)));
    env.push(prepared.env());
    let child = vk_peer::update::spawn_with(binary, Some(deadline), &env, &[fds.0, fds.1, fds.2])?;
    drop(prepared);
    // The child holds its ends now: its exit closes them, which `wait_prepared` sees.
    drop((ready_child, go_child));
    Ok(Started {
        child,
        ready: ready.into(),
        go: go.into(),
    })
}

/// Wait for the release to say it is prepared on `ready`, for at most `within`.
fn wait_prepared(mut ready: &std::fs::File, within: Duration) -> Result<()> {
    let mut poll = libc::pollfd {
        fd: ready.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let deadline = std::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            bail!("it was not prepared within {within:?}");
        }
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `poll` is one live pollfd.
        let n = unsafe { libc::poll(&mut poll, 1, ms) };
        if n > 0 {
            break;
        }
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e).context("waiting for the release");
            }
        }
    }
    let mut byte = [0u8; 1];
    match ready.read(&mut byte) {
        Ok(1) if byte == *b"p" => Ok(()),
        Ok(_) => bail!("it ended before it was prepared"),
        Err(e) => Err(e).context("reading from the release"),
    }
}

/// A pipe, both ends close-on-exec: (read, write).
fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 fills the two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("opening a pipe");
    }
    // SAFETY: both were just created and nothing else owns them.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn set_cloexec(fd: RawFd, on: bool) -> std::io::Result<()> {
    // SAFETY: F_GETFD and F_SETFD read and set a descriptor's flags and touch no memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = if on {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_overlap_marker_names_the_format() {
        assert!(OVERLAP_MARKER.ends_with(format!("-{FORMAT}").as_bytes()));
    }

    #[test]
    fn a_release_overlaps_only_when_it_can_and_a_manager_listens() {
        assert_eq!(Shape::from(true, true, true), Shape::Overlap);
        assert_eq!(Shape::from(true, true, false), Shape::Exec);
        assert_eq!(Shape::from(false, true, true), Shape::Exec);
        assert_eq!(Shape::from(false, false, true), Shape::Plain);
        assert_eq!(Shape::from(false, false, false), Shape::Plain);
    }

    /// The markers are found anywhere in the file, across the reads it takes.
    #[test]
    fn markers_are_found_across_reads() {
        let dir = std::env::temp_dir().join(format!("vk-registry-markers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("release");
        let mut bytes = vec![0u8; (1 << 20) - 5];
        bytes.extend_from_slice(OVERLAP_MARKER);
        bytes.extend_from_slice(&[0u8; 100]);
        std::fs::write(&path, &bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(markers(&file).unwrap(), (true, false));
        bytes.extend_from_slice(vk_peer::handoff::ENV.as_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(markers(&file).unwrap(), (true, true));
        std::fs::write(&path, b"nothing").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(markers(&file).unwrap(), (false, false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What is handed over reads back whole, from its start whatever read it before, and a
    /// format this release does not know is refused.
    #[test]
    fn what_is_carried_reads_back_from_its_start() {
        let m = lock::LockManager::new();
        let carried = Carried {
            format: FORMAT,
            at_ms: unix_ms(),
            locks: m.hand_over(),
            logins: vec![Login {
                state: "s".into(),
                target: "/".into(),
                verifier: "v".into(),
                left_ms: 1000,
            }],
        };
        let mut file = carry(&carried).unwrap();
        let mut skipped = Vec::new();
        file.read_to_end(&mut skipped).unwrap();
        let read = read_carried(&file).unwrap();
        assert_eq!(read.logins.len(), 1);
        assert_eq!(read.logins[0].verifier, "v");
        let other = Carried {
            format: FORMAT + 1,
            ..read
        };
        let file = carry(&other).unwrap();
        let Err(e) = read_carried(&file) else {
            panic!("a format this release does not know was read");
        };
        assert!(format!("{e:#}").contains("format"), "{e:#}");
    }

    /// The release says it is prepared and serves once told; told nothing — the registry
    /// gone — it must not serve. The registry sees a release that ended unprepared.
    #[test]
    fn a_release_serves_only_once_told_and_is_seen_ending_unprepared() {
        let both = |go: Option<&[u8]>| {
            let (ready_r, ready_w) = pipe().unwrap();
            let (go_r, go_w) = pipe().unwrap();
            let mut taken = Taken {
                pipes: Some((ready_w.into(), go_r.into())),
                ..Taken::default()
            };
            let mut go_w = std::fs::File::from(go_w);
            match go {
                Some(byte) => go_w.write_all(byte).unwrap(),
                None => drop(go_w),
            }
            let prepared = taken.prepared();
            (prepared, std::fs::File::from(ready_r))
        };
        let (prepared, ready) = both(None);
        assert!(prepared.is_err());
        wait_prepared(&ready, Duration::from_secs(5)).unwrap();
        let (prepared, _) = both(Some(b"x"));
        assert!(prepared.is_err());
        // A release that ends before it says anything.
        let (ready_r, ready_w) = pipe().unwrap();
        drop(ready_w);
        let e = wait_prepared(&std::fs::File::from(ready_r), Duration::from_secs(5)).unwrap_err();
        assert!(format!("{e:#}").contains("ended before"), "{e:#}");
        let (ready_r, _ready_w) = pipe().unwrap();
        let e =
            wait_prepared(&std::fs::File::from(ready_r), Duration::from_millis(50)).unwrap_err();
        assert!(format!("{e:#}").contains("within"), "{e:#}");
    }

    #[test]
    fn every_descriptor_variable_is_set_even_when_nothing_is_handed() {
        let env = fd_env(None, None);
        assert_eq!(env.len(), 3);
        assert!(env.iter().all(|(_, v)| v.is_empty()));
        let env = fd_env(Some(7), Some((8, 9)));
        assert_eq!(
            env.iter()
                .map(|(_, v)| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["7", "8", "9"]
        );
    }
}
