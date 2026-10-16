use crate::addr::SocketAddr;
use crate::framing::{DeSink, SerStream};
use crate::messages::{self, CmdExec, CmdResult, Message, RunMode, Status};
use crate::net::{listen, raw_connect_any};
use crate::pty;
use crate::status::get_status;
use anyhow::anyhow;
use futures::{Sink, SinkExt, Stream, StreamExt};
use log::{debug, error, info, warn};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process;
use std::process::Stdio;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::select;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::{task, time};

#[derive(Clone)]
pub struct TaskState {
    running_tasks: i32,
    last_activity: Option<Instant>,
}

impl TaskState {
    fn new() -> TaskState {
        TaskState {
            running_tasks: 0,
            last_activity: Some(Instant::now()),
        }
    }
    fn inc(&mut self) {
        // last_activity is left as-is: inactive() already returns false while
        // running_tasks != 0, and a task that ends WITHOUT counting as activity
        // (dec(false), the status-request path) must restore the previous idle
        // timestamp — clearing it here would disable the inactivity timeout for
        // good after the first status request.
        self.running_tasks += 1;
    }

    /// A finishing exec stamps the idle clock even while other connections are still open:
    /// `inactive()` ignores the stamp until `running_tasks` reaches zero, so waiting for the
    /// count to drop would only discard the exec's activity when a status request outlived it.
    fn dec(&mut self, update_last: bool) {
        self.running_tasks -= 1;
        if update_last {
            self.last_activity = Some(Instant::now());
        }
    }

    fn inactive(&self, duration: Duration) -> bool {
        if self.running_tasks != 0 {
            return false;
        }
        match self.last_activity {
            Some(t) => t.elapsed() > duration,
            None => false,
        }
    }
}

/// How often the accept loop re-checks for inactivity. Short timeouts are checked at their
/// own cadence; longer ones need no more than ten-second precision. Never zero — that would
/// panic `time::interval` — and with no timeout the check is a formality, so it idles.
fn inactivity_check_period(inactivity_timeout: Option<Duration>) -> Duration {
    inactivity_timeout
        .filter(|timeout| !timeout.is_zero())
        .map_or(Duration::from_secs(3600), |timeout| {
            timeout.min(Duration::from_secs(10))
        })
}

/// How much a served channel takes on ([`run_server`]).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The commands and connects running at once; `None` caps nothing.
    pub max_concurrent: Option<NonZeroUsize>,
    /// How long a new connection may take to send its request.
    pub first_message_timeout: Duration,
    /// Whether a background command may run. Without it, every command runs only as long as
    /// its session, and no child of the server outlives it unsupervised.
    pub background: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_concurrent: None,
            first_message_timeout: FIRST_MESSAGE_TIMEOUT,
            background: true,
        }
    }
}

/// Serve the exec channel on `socket`. `limits.max_concurrent` caps the commands and connects
/// running at once; one past the cap is refused with a `StartErr` rather than queued. A background
/// command counts until it exits, but not a process it double-forks away: the cap bounds
/// requests, not processes. Status probes are never refused, and a connection that names no
/// request within `limits.first_message_timeout` is closed, so neither takes up the cap. With
/// `exec_wrapper`, every command runs through it, `exec_wrapper_args` first ([`wrap_cmd`]).
pub async fn run_server(
    socket: &SocketAddr,
    inactivity_timeout: Option<Duration>,
    exec_wrapper: Option<PathBuf>,
    exec_wrapper_env: Vec<String>,
    exec_wrapper_args: Vec<String>,
    limits: Limits,
) -> Result<(), anyhow::Error> {
    run_server_routed(
        socket,
        inactivity_timeout,
        exec_wrapper,
        exec_wrapper_env,
        exec_wrapper_args,
        None,
        limits,
    )
    .await
}

/// A separate wrapper for commands named exactly `vk` on a wrapped channel
/// ([`run_server_routed`]).
#[derive(Debug, Clone)]
pub struct VkRoute {
    /// The program such a command is forced through.
    pub path: PathBuf,
    /// Arguments it gets first, before the requested command line.
    pub args: Vec<String>,
    /// The commands it runs at once; `None` caps nothing beyond `Limits::max_concurrent`.
    pub max_concurrent: Option<NonZeroUsize>,
}

/// [`run_server`], with a command named exactly `vk` forced through `vk_route` instead of
/// `exec_wrapper`: with the default environment allowlist only, and never in the background.
/// The route applies only beside an `exec_wrapper`; a channel without one runs everything
/// directly. `limits.max_concurrent` counts the commands of both routes together;
/// `vk_route.max_concurrent` caps the `vk` route's on top.
pub async fn run_server_routed(
    socket: &SocketAddr,
    inactivity_timeout: Option<Duration>,
    exec_wrapper: Option<PathBuf>,
    exec_wrapper_env: Vec<String>,
    exec_wrapper_args: Vec<String>,
    vk_route: Option<VkRoute>,
    limits: Limits,
) -> Result<(), anyhow::Error> {
    // Zero means no watchdog at all. Normalizing it away here keeps the rest of the function
    // from reading it as a timeout that has always already elapsed, and hands a zero-timeout
    // caller the fallback watchdog below like any other caller that asked for no timeout.
    let inactivity_timeout = inactivity_timeout.filter(|timeout| !timeout.is_zero());
    let status = Status::default();
    // Force every exec through this program (like SSH's ForceCommand): it receives
    // the requested command line as its arguments and decides what to run.
    // None = run requested commands directly (the default, unrestricted).
    let wrappers = Arc::new(
        exec_wrapper.map(|path| Wrappers::new(path, exec_wrapper_env, exec_wrapper_args, vk_route)),
    );
    let allow_background = limits.background;
    let first_message_timeout = limits.first_message_timeout;
    let limit = limits.max_concurrent.map(|n| Limit::new(n, "requests"));

    let listener = listen(socket)?;

    let state: Arc<Mutex<TaskState>> = Arc::new(Mutex::new(TaskState::new()));

    // The watchdog connects back to its own socket: only doable when serving a plain
    // unix socket path (under systemd the socket belongs to systemd, and a vsock
    // listener cannot connect to itself).
    if matches!(socket, SocketAddr::Unix(_)) && inactivity_timeout.is_none() {
        start_watchdog(status.clone(), socket.clone());
    }

    // Keep one interval across accept iterations: recreating a sleep after every connection
    // would let frequent status probes postpone the check even though they intentionally do
    // not reset last_activity.
    let mut inactivity_checks = time::interval(inactivity_check_period(inactivity_timeout));
    inactivity_checks.tick().await; // consume interval's immediate first tick

    loop {
        select! {
                _ = inactivity_checks.tick() => {
                    if let Some(inactivity_timeout) = inactivity_timeout {
                        let lock = state.lock().unwrap();
                        if lock.inactive(inactivity_timeout) {
                            info!(
                                "inactivity timeout: (pid={}, last activity={}s) exiting...",
                                std::process::id(),
                                lock.last_activity.unwrap().elapsed().as_secs()
                            );
                            process::exit(0);
                        }
                    }
                },
                result = listener.accept() => {
                    match result {
                Ok((stream, sink)) => {
                    let c_state = Arc::clone(&state);
                    let status = status.clone();
                    let wrappers = Arc::clone(&wrappers);
                    let limit = limit.clone();
                    {
                        let mut lock = c_state.lock().unwrap();
                        lock.inc();
                    }
                    // A new task is spawned for each socket. The socket is moved to the new task and processed there.
                    tokio::spawn(async move {
                        let mut update_last = true;
                        match do_handle_conn(&status, stream, sink, (*wrappers).as_ref(), limit.as_ref(), first_message_timeout, allow_background).await {
                            // A connection that failed before naming itself counts as activity:
                            // only a completed status request is known not to be one.
                            Err(e) => info!("{e}"),
                            Ok(skip_update) => {
                                if skip_update {
                                    update_last = false;
                                }
                            }
                        }
                        let mut lock = c_state.lock().unwrap();
                        lock.dec(update_last);
                        if update_last {
                            info!("task finished, current count: {}", lock.running_tasks);
                        }
                    });
                }
                Err(e) => error!("accept: {e}"),
                    }
            }
        }
    }
}

fn start_watchdog(status: Status, socket: SocketAddr) {
    let _forever = task::spawn(async move {
        info!(
            "watchdog: (pid={}) monitoring socket {}",
            std::process::id(),
            socket,
        );

        // check every 5s that we are still ok
        let mut interval = time::interval(Duration::from_millis(5000));
        loop {
            interval.tick().await;
            let current_status = get_status(&socket).await;
            match current_status {
                Ok(s) => {
                    if s == status {
                        continue;
                    }
                    info!(
                        "watchdog: (pid={}) invalid status, process has probably been replaced",
                        std::process::id()
                    );
                }
                Err(ref e) => {
                    info!(
                        "watchdog: (pid={}) error getting status: {}",
                        std::process::id(),
                        e
                    );
                }
            }
            info!("watchdog: (pid={}) exiting...", std::process::id());
            process::exit(1);
        }
    });
}

/// The cap on concurrent requests ([`Limits::max_concurrent`]).
#[derive(Clone)]
struct Limit {
    max: usize,
    permits: Arc<Semaphore>,
    /// Request kind named in the refusal message.
    what: &'static str,
}

impl Limit {
    fn new(max: NonZeroUsize, what: &'static str) -> Self {
        Limit {
            max: max.get(),
            permits: Arc::new(Semaphore::new(max.get())),
            what,
        }
    }

    /// A permit to run one request, held until it ends; `None` when `max` already run.
    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    fn refusal(&self) -> String {
        format!(
            "too many {} at once on this channel (at most {}); retry once one ends",
            self.what, self.max
        )
    }
}

static REQUEST_ID: AtomicUsize = AtomicUsize::new(1);

/// Client-supplied env var names always allowed through to the wrapper. These are
/// locale/timezone hints with no influence on how the wrapper resolves or loads
/// code, so they are safe to honour by default. Supports shell-style globs.
const WRAPPER_ENV_ALLOW_DEFAULTS: &[&str] = &["LANG", "LANGUAGE", "LC_*", "TZ"];

/// A configured exec wrapper: the program every exec is forced through, plus the
/// allowlist of client-supplied env var names permitted to reach it.
pub(crate) struct ExecWrapper {
    path: PathBuf,
    /// Glob patterns (defaults + admin `--exec-wrapper-env`) matched against env
    /// var names; client env not matching any pattern is dropped before the
    /// wrapper runs, so it cannot be subverted (LD_PRELOAD, BASH_ENV, ...).
    env_allow: Vec<String>,
    /// Arguments the wrapper gets first, before the requested command line.
    args: Vec<String>,
}

impl ExecWrapper {
    pub(crate) fn new(path: PathBuf, extra_env_allow: Vec<String>, args: Vec<String>) -> Self {
        let mut env_allow: Vec<String> = WRAPPER_ENV_ALLOW_DEFAULTS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        env_allow.extend(extra_env_allow);
        Self {
            path,
            env_allow,
            args,
        }
    }

    fn env_allowed(&self, name: &str) -> bool {
        self.env_allow.iter().any(|pat| glob_match(pat, name))
    }
}

/// The main wrapper and an optional wrapper for commands named exactly `vk`, with its own cap.
struct Wrappers {
    main: ExecWrapper,
    vk: Option<(ExecWrapper, Option<Limit>)>,
}

impl Wrappers {
    /// Build the main wrapper from `path`, `env_allow` and `args`; the `vk` route
    /// never receives `env_allow`.
    fn new(
        path: PathBuf,
        env_allow: Vec<String>,
        args: Vec<String>,
        vk_route: Option<VkRoute>,
    ) -> Self {
        Self {
            main: ExecWrapper::new(path, env_allow, args),
            vk: vk_route.map(|r| {
                let limit = r.max_concurrent.map(|n| Limit::new(n, "`vk` commands"));
                (ExecWrapper::new(r.path, Vec::new(), r.args), limit)
            }),
        }
    }
}

/// Select the wrapper, if any, the route's own cap, if any, and an optional background
/// refusal reason. Commands named exactly `vk` use the `vk` route when configured, in the
/// foreground only. All other names, including paths to `vk`, use the main wrapper.
fn route<'a>(
    cmd: &CmdExec,
    wrappers: Option<&'a Wrappers>,
    allow_background: bool,
) -> (
    Option<&'a ExecWrapper>,
    Option<&'a Limit>,
    Option<&'static str>,
) {
    const CHANNEL_REFUSAL: &str = "background commands are refused on this channel";
    let channel_refusal = (!allow_background).then_some(CHANNEL_REFUSAL);
    match wrappers {
        None => (None, None, channel_refusal),
        Some(Wrappers {
            vk: Some((vk, limit)),
            ..
        }) if cmd.name == "vk" => (
            Some(vk),
            limit.as_ref(),
            Some(if allow_background {
                "background commands are refused for `vk` on this channel"
            } else {
                CHANNEL_REFUSAL
            }),
        ),
        Some(w) => (Some(&w.main), None, channel_refusal),
    }
}

/// Minimal shell-style glob match supporting `*` (any run, incl. empty) and `?`
/// (one char), used to match env var names against the wrapper allowlist (like
/// SSH's `AcceptEnv`). No character classes — env var names don't need them.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    let (mut pi, mut si) = (0, 0);
    // Position to backtrack to when a `*` needs to consume one more char.
    let (mut star, mut star_si) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_si = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The variable a wrapped command's requested working directory reaches the wrapper in
/// ([`wrap_cmd`]); empty when the client named none.
pub const WRAPPER_DIR_ENV: &str = "VK_EXEC_DIR";

/// Rewrite a request to run through the exec wrapper: the wrapper becomes the command, and
/// the originally-requested name + args become its arguments. Nothing the client sends
/// decides how the wrapper itself runs:
/// - it runs as the server's own user, whatever user the client names — not even the
///   server's default run user, which the server could not switch to unprivileged;
/// - it runs in the server's working directory, never entering one the client names (which
///   would tell the client whether that directory exists): the client's dir reaches the
///   wrapper as [`WRAPPER_DIR_ENV`], to check before it enters it;
/// - client env is filtered to the wrapper's allowlist, and the client cannot clear the
///   (trusted) server env the wrapper inherits;
/// - a tty keeps the client's size and modes, but its `TERM` only when the allowlist has it.
fn wrap_cmd(mut cmd: CmdExec, wrapper: &ExecWrapper) -> CmdExec {
    let mut args = Vec::with_capacity(wrapper.args.len() + cmd.args.len() + 1);
    args.extend(wrapper.args.iter().cloned());
    args.push(std::mem::take(&mut cmd.name));
    args.append(&mut cmd.args);
    cmd.name = wrapper.path.to_string_lossy().into_owned();
    cmd.args = args;
    cmd.env.retain(|e| {
        let key = e.split_once('=').map_or(e.as_str(), |(k, _)| k);
        wrapper.env_allowed(key)
    });
    cmd.clear_env = false;
    cmd.user = Some(String::new());
    let dir = cmd.dir.take().unwrap_or_default();
    cmd.env.push(format!("{WRAPPER_DIR_ENV}={dir}"));
    if let Some(tty) = &mut cmd.tty
        && !wrapper.env_allowed("TERM")
    {
        tty.term = None;
    }
    cmd
}

async fn do_handle_conn(
    status: &Status,
    mut stream: SerStream,
    sink: DeSink,
    wrappers: Option<&Wrappers>,
    limit: Option<&Limit>,
    first_message_timeout: Duration,
    allow_background: bool,
) -> Result<bool, anyhow::Error> {
    let client_request = time::timeout(first_message_timeout, stream.next())
        .await
        .map_err(|_| anyhow!("no request within {first_message_timeout:?}"))?
        .ok_or(anyhow!("no data"))??;
    // A command or a connect takes a permit, held until it ends; a status probe does not, so
    // a full channel still answers the watchdog's.
    let permit = match (&client_request, limit) {
        (Message::CmdExec(_) | Message::CmdConnect { .. }, Some(limit)) => {
            match limit.try_acquire() {
                Some(permit) => Some(permit),
                None => {
                    let msg = limit.refusal();
                    // The refusal is the session's only reply; a client already gone has
                    // nothing left to tell.
                    let _ = send_last(stream, sink, Message::StartErr { msg: msg.clone() }).await;
                    return Err(anyhow!(msg));
                }
            }
        }
        _ => None,
    };

    match client_request {
        Message::CmdExec(cmd) => {
            let (exec_wrapper, route_limit, background_refused) =
                route(&cmd, wrappers, allow_background);
            if let Some(refused) = background_refused
                && cmd.mode == RunMode::Background
            {
                let msg = refused.to_string();
                // The refusal is the session's only reply; a client already gone has nothing
                // left to tell.
                let _ = send_last(stream, sink, Message::StartErr { msg: msg.clone() }).await;
                return Err(anyhow!(msg));
            }
            // A route with a cap of its own runs only in the foreground, so its permit is held
            // here, until the command ends.
            let _route_permit = match route_limit {
                Some(limit) => match limit.try_acquire() {
                    Some(permit) => Some(permit),
                    None => {
                        let msg = limit.refusal();
                        let _ =
                            send_last(stream, sink, Message::StartErr { msg: msg.clone() }).await;
                        return Err(anyhow!(msg));
                    }
                },
                None => None,
            };
            let cmd = match exec_wrapper {
                Some(w) => wrap_cmd(cmd, w),
                None => cmd,
            };
            let req_id = REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if cmd.tty.is_some() {
                srv_run_cmd_tty(req_id, stream, sink, cmd)
                    .await
                    .and(Ok(false))
            } else {
                srv_run_cmd(req_id, stream, sink, cmd, permit)
                    .await
                    .and(Ok(false))
            }
        }
        Message::CmdStatus => {
            let status = status.clone();
            send_last(stream, sink, Message::RespStatus { status }).await?;
            Ok(true)
        }
        Message::CmdConnect { target } => {
            // A wrapped channel is a restricted one (the host-exec allowlist a guest's
            // requests are forced through): it has no notion of wrapping an arbitrary
            // dial the way it wraps a command, so a raw connect on it would bypass the
            // allowlist entirely instead of being subject to it. Refuse outright —
            // CmdConnect is only for a channel the dialing side already trusts fully
            // (the guest's own control port, as `vk exec`/`vk status` already use).
            if wrappers.is_some() {
                let msg = "connect is refused on a wrapped (host-exec) channel".to_string();
                let _ = send_last(stream, sink, Message::StartErr { msg: msg.clone() }).await;
                return Err(anyhow!(msg));
            }
            let req_id = REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let addrs = match crate::net::resolve_connect_target(&target).await {
                Ok(a) => a,
                Err(e) => {
                    let msg = format!("invalid connect target {target:?}: {e:#}");
                    let _ = send_last(stream, sink, Message::StartErr { msg: msg.clone() }).await;
                    return Err(anyhow!("connect [{req_id}] {msg}"));
                }
            };
            srv_run_connect(req_id, stream, sink, &addrs)
                .await
                .and(Ok(false))
        }
        _ => Err(anyhow!("invalid message")),
    }
}

fn build_command(cmd: &CmdExec, user: Option<SessionUser>) -> Command {
    let mut command = Command::new(&cmd.name);
    command.args(&cmd.args);
    if cmd.clear_env {
        command.env_clear();
    }
    for e in &cmd.env {
        if let Some((k, v)) = e.split_once('=') {
            command.env(k, v);
        }
    }
    if let Some(dir) = &cmd.dir {
        command.current_dir(dir);
    }
    if let Some(user) = user {
        apply_user(&mut command, cmd, user);
    }
    command
}

/// The command's user spec and its lookup result.
struct SessionUser {
    spec: String,
    resolved: std::io::Result<ResolvedUser>,
}

/// Who `cmd` runs as: its per-command override, else the guest's default (the image's
/// USER, exported as VIRTKIT_DEFAULT_RUN_USER by the microVM init). `None` keeps the
/// agent's own user.
fn session_user(cmd: &CmdExec) -> Option<SessionUser> {
    run_as(
        cmd.user.as_deref(),
        std::env::var("VIRTKIT_DEFAULT_RUN_USER").ok(),
    )
    .map(|spec| SessionUser {
        resolved: resolve_user(&spec),
        spec,
    })
}

/// Resolve which Unix user to drop to: the per-command override wins, otherwise the
/// guest default. An empty name on either side means "keep the current user", so an
/// explicit `Some("")` both skips the fallback and drops no privileges — the escape
/// hatch a caller already running unprivileged needs, since `apply_user` would
/// otherwise call `setgroups` and fail with EPERM even for its own uid.
///
/// The order matters: the override must be consulted before it is tested for
/// emptiness, or an empty one would fall through to the default it is meant to
/// suppress.
fn run_as(requested: Option<&str>, default: Option<String>) -> Option<String> {
    requested
        .map(str::to_owned)
        .or(default)
        .filter(|u| !u.is_empty())
}

pub struct ResolvedUser {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub home: Option<std::ffi::OsString>,
    // only the ssh server (in vk-agent) reads the login shell
    pub shell: Option<std::ffi::OsString>,
    pub groups: Vec<libc::gid_t>,
}

/// Split a Docker `USER` value into its user part and optional group part: the first
/// `:` separates them (`user`, `user:group`, `uid:gid`, `uid:group`, `user:gid`).
fn split_user_group(spec: &str) -> (&str, Option<&str>) {
    match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    }
}

/// A resolved passwd entry (or a bare numeric uid that has none).
struct PasswdInfo {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: Option<std::ffi::OsString>,
    shell: Option<std::ffi::OsString>,
    /// The user's name, to feed getgrouplist. `None` for a bare numeric uid with no
    /// passwd entry (nothing to enumerate supplementary groups against).
    name: Option<std::ffi::CString>,
}

enum PasswdKey<'a> {
    Name(&'a std::ffi::CStr),
    Uid(libc::uid_t),
}

/// Buffer limit for getpw*_r / getgrnam_r retries on ERANGE. Entry strings,
/// especially long group member lists, can exceed the initial 4 KiB.
const MAX_NSS_BUF: usize = 1 << 20;

/// Whether a getpw*_r / getgr*_r error code means "no such entry". POSIX specifies 0 with
/// a null result for a missing entry, but glibc reports a database it cannot open (no
/// /etc/passwd or /etc/group in a scratch image, an NSS backend that is unavailable), and
/// musl a missing /etc/passwd or /etc/group, as ENOENT; getpwnam_r(3) lists ESRCH among
/// the codes seen for "not found". EBADF and
/// EPERM, listed there too, are real faults on Linux and stay errors.
fn nss_not_found(rc: libc::c_int) -> bool {
    matches!(rc, libc::ENOENT | libc::ESRCH)
}

/// getpwnam_r / getpwuid_r into a [`PasswdInfo`]; `Ok(None)` when there is no such entry.
fn passwd_lookup(key: PasswdKey) -> std::io::Result<Option<PasswdInfo>> {
    use std::io::Error;
    use std::os::unix::ffi::OsStrExt;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        let rc = unsafe {
            match key {
                PasswdKey::Name(n) => libc::getpwnam_r(
                    n.as_ptr(),
                    &mut pwd,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                ),
                PasswdKey::Uid(u) => {
                    libc::getpwuid_r(u, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
                }
            }
        };
        match rc {
            0 => break,
            rc if nss_not_found(rc) => return Ok(None),
            libc::ERANGE if buf.len() < MAX_NSS_BUF => buf.resize(buf.len() * 2, 0),
            _ => return Err(Error::from_raw_os_error(rc)),
        }
    }
    if result.is_null() {
        return Ok(None);
    }
    let osstr = |p: *const libc::c_char| -> Option<std::ffi::OsString> {
        if p.is_null() {
            return None;
        }
        let b = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
        (!b.is_empty()).then(|| std::ffi::OsStr::from_bytes(b).to_os_string())
    };
    let name = (!pwd.pw_name.is_null())
        .then(|| unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }.to_owned());
    Ok(Some(PasswdInfo {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: osstr(pwd.pw_dir),
        shell: osstr(pwd.pw_shell),
        name,
    }))
}

/// Resolve the user part of a `USER` value: a numeric uid (its passwd entry if any, else
/// a bare uid with gid 0 — like `docker run --user <uid>` for an uid absent from
/// /etc/passwd, or with no passwd database to ask) or a name (getpwnam).
fn resolve_passwd(user: &str) -> std::io::Result<PasswdInfo> {
    use std::io::{Error, ErrorKind};
    if let Ok(uid) = user.parse::<libc::uid_t>() {
        return Ok(passwd_lookup(PasswdKey::Uid(uid))?.unwrap_or(PasswdInfo {
            uid,
            gid: 0,
            home: None,
            shell: None,
            name: None,
        }));
    }
    let c_name = std::ffi::CString::new(user)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "user name contains NUL"))?;
    passwd_lookup(PasswdKey::Name(&c_name))?
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("unknown user {user:?}")))
}

/// Resolve the group part of a `USER` value to a gid: numeric as-is, else getgrnam.
fn resolve_gid(group: &str) -> std::io::Result<libc::gid_t> {
    use std::io::{Error, ErrorKind};
    if let Ok(gid) = group.parse::<libc::gid_t>() {
        return Ok(gid);
    }
    let c = std::ffi::CString::new(group)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "group name contains NUL"))?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    let unknown = || Error::new(ErrorKind::NotFound, format!("unknown group {group:?}"));
    loop {
        let rc = unsafe {
            libc::getgrnam_r(
                c.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        match rc {
            0 => break,
            rc if nss_not_found(rc) => return Err(unknown()),
            libc::ERANGE if buf.len() < MAX_NSS_BUF => buf.resize(buf.len() * 2, 0),
            _ => return Err(Error::from_raw_os_error(rc)),
        }
    }
    if result.is_null() {
        return Err(unknown());
    }
    Ok(grp.gr_gid)
}

/// The supplementary group list a named user belongs to (getgrouplist), including
/// `primary`. Sizes the buffer up if the first call reports more.
fn grouplist(name: &std::ffi::CStr, primary: libc::gid_t) -> Vec<libc::gid_t> {
    let mut ngroups: libc::c_int = 32;
    let mut groups: Vec<libc::gid_t> = vec![0; ngroups as usize];
    loop {
        let rc = unsafe {
            libc::getgrouplist(name.as_ptr(), primary, groups.as_mut_ptr(), &mut ngroups)
        };
        if rc >= 0 {
            groups.truncate(ngroups as usize);
            break;
        }
        groups.resize(ngroups as usize, 0);
    }
    groups
}

/// Resolve a Docker `USER` value (`user`, `user:group`, `uid`, `uid:gid`, and the mixed
/// name/number forms) to the ids to drop to. Names go through getpwnam/getgrnam, numeric
/// ids are taken as-is; an explicit group overrides the user's primary gid and, matching
/// Docker, replaces the supplementary group set with just that group. Done in the parent —
/// getpw*_r / getgrouplist are not async-signal-safe, so must not run in pre_exec.
pub fn resolve_user(spec: &str) -> std::io::Result<ResolvedUser> {
    let (user_part, group_part) = split_user_group(spec);
    let pw = resolve_passwd(user_part)?;
    let mut gid = pw.gid;
    let groups = if let Some(g) = group_part {
        gid = resolve_gid(g)?;
        vec![gid]
    } else if let Some(name) = &pw.name {
        grouplist(name, pw.gid)
    } else {
        vec![gid]
    };
    Ok(ResolvedUser {
        uid: pw.uid,
        gid,
        home: pw.home,
        shell: pw.shell,
        groups,
    })
}

/// How long a hung-up process group gets to leave before it is killed outright.
const HANGUP_GRACE: Duration = Duration::from_secs(5);

/// Send `signal` to the process group `child` leads. Only the task that reaps `child`
/// may call this: until then its pid, and so its group id, cannot be reused.
fn signal_group(child: &tokio::process::Child, signal: libc::c_int) {
    if let Some(pid) = child.id().and_then(|p| libc::pid_t::try_from(p).ok()) {
        // SAFETY: a plain syscall; ESRCH (the group already gone) is fine to ignore.
        unsafe { libc::kill(-pid, signal) };
    }
}

/// Hang up on `child`'s process group, as sshd does when its client leaves, and reap it.
/// A group still there when the grace period ends is killed: its client is gone, so
/// nothing it runs is still wanted, and a session must not wait forever on a process
/// that ignores the hang-up.
pub async fn hangup_and_reap(
    child: &mut tokio::process::Child,
) -> std::io::Result<process::ExitStatus> {
    signal_group(child, libc::SIGHUP);
    match time::timeout(HANGUP_GRACE, child.wait()).await {
        Ok(status) => status,
        Err(_) => {
            signal_group(child, libc::SIGKILL);
            child.wait().await
        }
    }
}

/// Hand a pty slave to the user a session runs as, the way sshd does: owned by them, in
/// the `tty` group with mode 0620 when the guest has one, else in `gid` with 0600. An
/// agent that is not root already owns the slave and serves only itself.
pub fn give_tty(slave: impl AsFd, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let (gid, mode) = match resolve_gid("tty") {
        Ok(tty) => (tty, 0o620),
        Err(e) if e.kind() == ErrorKind::NotFound => (gid, 0o600),
        Err(e) => return Err(Error::new(e.kind(), format!("tty group: {e}"))),
    };
    let fd = slave.as_fd().as_raw_fd();
    if unsafe { libc::fchown(fd, uid, gid) } != 0 {
        let e = Error::last_os_error();
        return Err(Error::new(e.kind(), format!("fchown {uid}:{gid}: {e}")));
    }
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        let e = Error::last_os_error();
        return Err(Error::new(e.kind(), format!("fchmod {mode:o}: {e}")));
    }
    Ok(())
}

/// Configure `command` to exec as `user`: set HOME/USER/LOGNAME (unless the
/// caller already provided them) and register a pre_exec that drops privileges.
fn apply_user(command: &mut Command, cmd: &CmdExec, user: SessionUser) {
    let has_env = |key: &str| {
        cmd.env
            .iter()
            .any(|e| e.split_once('=').map(|(k, _)| k == key).unwrap_or(false))
    };

    let SessionUser { spec, resolved } = user;
    match resolved {
        Ok(ru) => {
            // USER/LOGNAME name the login user, so export only the user part — never the
            // raw `user:group` spec, whose group half is not part of the name.
            let login = split_user_group(&spec).0;
            if !cmd.clear_env && !has_env("USER") {
                command.env("USER", login);
            }
            if !cmd.clear_env && !has_env("LOGNAME") {
                command.env("LOGNAME", login);
            }
            if let Some(home) = ru.home.as_ref().filter(|_| !has_env("HOME")) {
                command.env("HOME", home);
            }
            let (uid, gid, groups) = (ru.uid, ru.gid, ru.groups);
            // pre_exec runs after fork, before exec: only async-signal-safe
            // syscalls. setgroups before setgid before setuid, so the group
            // changes still have the privilege they require.
            unsafe {
                command.pre_exec(move || {
                    if libc::setgroups(groups.len() as libc::size_t, groups.as_ptr()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setgid(gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        Err(e) => {
            // Can't fail build_command's signature; surface it as a spawn error.
            let msg = format!("virtkit-agent: cannot run as user {spec:?}: {e}");
            unsafe {
                command.pre_exec(move || Err(std::io::Error::other(msg.clone())));
            }
        }
    }
}

/// Once the command exits, its trailing output is already sitting in the pipe or pty
/// buffer, so draining it to the client takes milliseconds. Bound that drain anyway:
/// the reader tasks end on end-of-file, and a process the command left behind — a
/// daemon, or anything that survives the SIGHUP the kernel sends when a pty's session
/// leader exits — holds the other end open and never lets that happen, so an unbounded
/// drain would leave the session hanging after the command itself is long gone. The
/// bound is wall clock, not progress: a client too slow to take 500ms of output loses
/// the tail, which beats hanging on it.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_millis(500);

/// Wait for one of a command's stdio tasks to run out of work, giving up at `deadline`;
/// the returned flag says whether it got there on its own. Reaps the task either way —
/// that is what drops its end of the command's stdio, so the pipe or pty is closed by
/// the time the session ends — and propagates a panic inside it, which must not pass
/// for a clean drain.
async fn drain_until(
    handle: &mut task::JoinHandle<()>,
    deadline: time::Instant,
) -> Result<bool, task::JoinError> {
    if let Ok(joined) = time::timeout_at(deadline, &mut *handle).await {
        return joined.map(|()| true);
    }
    handle.abort();
    match handle.await {
        Ok(()) => Ok(false),
        // the cancellation we just asked for
        Err(err) if err.is_cancelled() => Ok(false),
        Err(err) => Err(err),
    }
}

/// `exec --tty`: run the command on a pty. One output stream (the terminal, sent as
/// Fd::Stdout), stdin bytes go to the master, Resize messages drive TIOCSWINSZ.
async fn srv_run_cmd_tty(
    req_id: usize,
    mut stream: impl Stream<Item = Result<Message, std::io::Error>>
    + std::marker::Unpin
    + Send
    + 'static,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    cmd: CmdExec,
) -> Result<(), anyhow::Error> {
    info!("command [{}] {} (tty)", req_id, cmd);
    let Some(tty) = &cmd.tty else { unreachable!() };
    if cmd.mode == RunMode::Background {
        let msg = "--tty is incompatible with --background".to_string();
        send_last(stream, sink, Message::StartErr { msg: msg.clone() }).await?;
        return Err(anyhow!("command [{req_id}] {msg}"));
    }

    let (master, slave) = match pty::openpty(tty.rows, tty.cols) {
        Ok(pair) => pair,
        Err(e) => {
            let msg = format!("openpty: {e}");
            send_last(stream, sink, Message::StartErr { msg }).await?;
            return Err(anyhow!("command [{req_id}] openpty: {e}"));
        }
    };

    // The client terminal's modes, as sshd applies a pty request's; the kernel's
    // defaults still make a usable terminal.
    if let Err(e) = pty::apply_terminal_modes(slave.as_raw_fd(), &tty.modes) {
        warn!("command [{req_id}] terminal modes left at their defaults: {e}");
    }
    // Give the terminal to the session user. Lookup errors surface at spawn; a
    // root-owned pty remains usable through inherited fds.
    let user = session_user(&cmd);
    if let Some(ru) = user.as_ref().and_then(|u| u.resolved.as_ref().ok())
        && let Err(e) = give_tty(&slave, ru.uid, ru.gid)
    {
        warn!("command [{req_id}] pty owner: {e}");
    }
    let mut command = build_command(&cmd, user);
    if let Some(term) = &tty.term {
        command.env("TERM", term);
    }
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .kill_on_drop(true);
    // New session with the pty as controlling terminal: job control, SIGWINCH and
    // ^C/^Z dispatch work like on a real terminal. setsid() also makes the child a
    // process group leader, so the disconnect path can kill the whole group.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            send_last(stream, sink, Message::StartErr { msg: e.to_string() }).await?;
            return Err(anyhow!("command [{req_id}] error starting process: {e}"));
        }
    };
    // the Command holds the slave Stdio fds: drop it so the master reads EIO (eof)
    // once the command and its children are gone
    drop(command);

    sink.send(Message::StartOK).await?;

    let master_fd = master.as_raw_fd();
    let (master_read, mut master_write) = tokio::io::split(master);

    let (tx, rx) = mpsc::channel(super::DATA_CHANNEL_CAPACITY);

    let writer = tokio::spawn(writer_task(rx, sink, req_id));

    let tx_out = tx.clone();
    let mut copy_out = tokio::spawn(async move {
        reader_task(req_id, crate::messages::Fd::Stdout, master_read, tx_out).await;
    });

    // The reader reports a client that went away; the hang-up is this task's, which
    // reaps the command, so no signal can reach a group whose leader was reaped.
    let (gone_tx, mut gone) = oneshot::channel();
    // `stop` cancels the reader wherever it waits, a write to a full pty included.
    let (stop_reader, stop) = oneshot::channel::<()>();
    let client_stream_reader = tokio::spawn(async move {
        let read = async {
            loop {
                match stream.next().await {
                    Some(Ok(Message::Data {
                        fd: messages::Fd::Stdin,
                        msg,
                    })) => {
                        if master_write.write_all(&msg).await.is_err() {
                            break false;
                        }
                    }
                    Some(Ok(Message::Resize { rows, cols })) => {
                        // master_write (same underlying fd) outlives this task: the fd
                        // stays valid for the ioctl
                        let _ = pty::set_winsize(master_fd, rows, cols);
                    }
                    // no tty equivalent of half-closing stdin: ignore Close
                    Some(Ok(_)) => {}
                    None | Some(Err(_)) => break true,
                }
            }
        };
        let disconnected = select! {
            _ = stop => false,
            disconnected = read => disconnected,
        };
        // Its half of the master goes before the hang-up that follows.
        drop(master_write);
        if disconnected {
            let _ = gone_tx.send(());
        }
        stream
    });

    let mut hung_up = false;
    let status = select! {
        status = child.wait() => status?,
        Ok(()) = &mut gone => {
            info!("command [{req_id}] client disconnected, hanging up the command");
            hung_up = true;
            // Closing the master hangs up the session leader and ends the tty for every
            // job on it, as a terminal would; the stream reader has dropped its half.
            copy_out.abort();
            let _ = (&mut copy_out).await;
            hangup_and_reap(&mut child).await?
        }
    };

    debug!("command [{req_id}] exit status: {status}");
    // Await the reader's end, which drops its half of the master.
    let _ = stop_reader.send(());
    // A panicked reader drops the stream: still report the exit without lingering.
    let stream = client_stream_reader
        .await
        .inspect_err(|e| error!("command [{req_id}] client stream reader: {e}"))
        .ok();
    if hung_up {
        // the output copy is gone already
    } else if status.signal().is_some() {
        copy_out.abort();
        let _ = copy_out.await;
    } else if !drain_until(&mut copy_out, time::Instant::now() + OUTPUT_DRAIN_GRACE).await? {
        // no EIO within the grace period: a process outliving the command still holds a
        // slave handle. Report the exit rather than wait on a pty nobody is reading.
        info!("command [{req_id}] pty still held after exit, ending the session anyway");
    }
    // both halves of the master are dropped by now, so the pty is closed and whatever
    // still holds a slave sees its terminal go away
    let _ = tx
        .send(Message::ExecDone(CmdResult {
            code: status.code(),
            signal: status.signal(),
        }))
        .await;
    drop(tx);
    let sink = writer.await?;
    if let Some(stream) = stream {
        linger(stream, sink).await;
    }
    info!("command [{req_id}] done ({status})");

    Ok(())
}

async fn srv_run_cmd(
    req_id: usize,
    mut stream: impl Stream<Item = Result<Message, std::io::Error>>
    + std::marker::Unpin
    + Send
    + 'static,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    cmd: CmdExec,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<(), anyhow::Error> {
    info!("command [{}] {}", req_id, cmd);
    let mut command = build_command(&cmd, session_user(&cmd));

    match cmd.mode {
        RunMode::Background => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        }
        RunMode::Interactive => {
            // own process group so that a client disconnect can kill the whole
            // process tree, not just the direct child (see client_stream_reader)
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .kill_on_drop(true);
        }
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            send_last(stream, sink, Message::StartErr { msg: e.to_string() }).await?;
            return Err(anyhow!("command [{req_id}] error starting process: {e}",));
        }
    };

    if cmd.mode == RunMode::Background {
        info!("command [{req_id}] background task started");
        // A background command counts against the cap until it exits, not just until it
        // starts. Its exit status has no one to go to.
        if let Some(permit) = permit {
            tokio::spawn(async move {
                let _ = child.wait().await;
                drop(permit);
            });
        }
        send_last(stream, sink, Message::StartOK).await?;
        return Ok(());
    }
    sink.send(Message::StartOK).await?;

    let (tx, rx) = mpsc::channel(super::DATA_CHANNEL_CAPACITY);

    // async task to send messages using the unix socket
    // other tasks can use tx clones to send messages
    let writer = tokio::spawn(writer_task(rx, sink, req_id));

    // async task to read from stdout
    let tx_out = tx.clone();
    let stdout = child.stdout.take().unwrap();
    let mut copy_out = tokio::spawn(async move {
        reader_task(req_id, crate::messages::Fd::Stdout, stdout, tx_out).await;
    });

    // async task to read from stderr
    let tx_err = tx.clone();
    let stderr = child.stderr.take().unwrap();
    let mut copy_err = tokio::spawn(async move {
        reader_task(req_id, crate::messages::Fd::Stderr, stderr, tx_err).await;
    });

    // stdin writing thread
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(super::DATA_CHANNEL_CAPACITY);

    let mut stdin_tx = Some(stdin_tx);

    let mut stdin = child.stdin.take().unwrap();

    let mut write_stdin = tokio::spawn(async move {
        while let Some(data) = stdin_rx.recv().await {
            debug!("copy_stdin_task, writing {} bytes", data.len());
            if stdin.write_all(&data).await.is_ok() {
                debug!("copy_stdin_task, wrote {} bytes", data.len());
            } else {
                break;
            }
        }
        debug!("copy_stdin_task done");
        let _ = stdin.flush().await;
    });

    // The reader reports a client that went away; the kill is this task's, which reaps
    // the command, so no signal can reach a group whose leader was reaped.
    let (gone_tx, mut gone) = oneshot::channel();
    // `stop` cancels the reader wherever it waits, a send to a full stdin channel included.
    let (stop_reader, stop) = oneshot::channel::<()>();
    let client_stream_reader = tokio::spawn(async move {
        let read = async {
            loop {
                let client_msg = match stream.next().await {
                    Some(Ok(msg)) => msg,
                    // EOF or framing error: the client is gone — it never closes the
                    // connection while the command runs (stdin end-of-input is signaled
                    // with a Close message, not by closing the socket)
                    None | Some(Err(_)) => break true,
                };
                match client_msg {
                    Message::Data {
                        fd: messages::Fd::Stdin,
                        msg,
                    } => {
                        debug!("writing to stdin {} bytes", msg.len());
                        if let Some(ref tx) = stdin_tx {
                            let _ = tx.send(msg).await;
                        } else {
                            error!("attempt to write to stdin after it is closed");
                            break false;
                        }
                    }
                    Message::Close {
                        fd: messages::Fd::Stdin,
                        error,
                    } => {
                        if let Some(err) = error {
                            debug!("got close message on stdin with error {err}");
                        }
                        debug!("closing stdin from msg");
                        stdin_tx = None;
                    }
                    _ => {}
                }
            }
        };
        let disconnected = select! {
            _ = stop => false,
            disconnected = read => disconnected,
        };
        if disconnected {
            let _ = gone_tx.send(());
        }
        stream
    });

    let status = select! {
        status = child.wait() => status?,
        // Nobody is listening anymore: kill the command instead of letting it run
        // unattended (Ctrl-C on the client side must stop the remote command). The
        // child is its own process group leader, so signal the whole group: a bare
        // kill(pid) would orphan grandchildren (e.g. `sh -c '...; sleep 60'`).
        Ok(()) = &mut gone => {
            info!("command [{req_id}] client disconnected, killing its process group");
            signal_group(&child, libc::SIGKILL);
            child.wait().await?
        }
    };

    debug!("command [{req_id}] exit status: {status}");
    let _ = tx
        .send(Message::Close {
            fd: crate::messages::Fd::Stdin,
            error: None,
        })
        .await;
    // Await the reader's end, which drops the stdin channel and ends write_stdin.
    let _ = stop_reader.send(());
    // A panicked reader drops the stream: still report the exit without lingering.
    let stream = client_stream_reader
        .await
        .inspect_err(|e| error!("command [{req_id}] client stream reader: {e}"))
        .ok();
    if status.signal().is_some() {
        copy_out.abort();
        copy_err.abort();
        write_stdin.abort();
    } else {
        // one budget for the three of them, not one each
        let deadline = time::Instant::now() + OUTPUT_DRAIN_GRACE;
        let drained = drain_until(&mut copy_out, deadline).await?
            & drain_until(&mut copy_err, deadline).await?
            & drain_until(&mut write_stdin, deadline).await?;
        if !drained {
            info!("command [{req_id}] stdio still held after exit, ending the session anyway");
        }
    }
    let _ = tx
        .send(Message::ExecDone(CmdResult {
            code: status.code(),
            signal: status.signal(),
        }))
        .await;
    debug!("command [{req_id}] execDone sent");
    drop(tx);
    let sink = writer.await?;
    if let Some(stream) = stream {
        linger(stream, sink).await;
    }
    info!("command [{req_id}] done ({status})");

    Ok(())
}

/// `CmdConnect`: dial `targets` — the addresses the target name resolved to, tried in
/// order (see [`raw_connect_any`]) — and splice raw bytes to the one that accepts,
/// framed the same way a `CmdExec`'s stdio is (see [`Message::CmdConnect`]). Reuses
/// the exec session's `reader_task`/`writer_task` pump against the dialed connection
/// instead of a child process's stdio — one stream each way (Stdout out, Stdin in),
/// no exit code.
async fn srv_run_connect(
    req_id: usize,
    mut stream: impl Stream<Item = Result<Message, std::io::Error>>
    + std::marker::Unpin
    + Send
    + 'static,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    targets: &[SocketAddr],
) -> Result<(), anyhow::Error> {
    let conn = match raw_connect_any(targets).await {
        Ok((conn, target)) => {
            info!("connect [{req_id}] {target}");
            conn
        }
        Err(e) => {
            send_last(stream, sink, Message::StartErr { msg: e.to_string() }).await?;
            return Err(anyhow!("connect [{req_id}] {e:#}"));
        }
    };
    sink.send(Message::StartOK).await?;

    let (read_half, mut write_half) = tokio::io::split(conn);
    let (tx, rx) = mpsc::channel(super::DATA_CHANNEL_CAPACITY);

    let writer = tokio::spawn(writer_task(rx, sink, req_id));

    let copy_out = tokio::spawn(async move {
        reader_task(req_id, messages::Fd::Stdout, read_half, tx).await;
    });

    let client_stream_reader = tokio::spawn(async move {
        loop {
            match stream.next().await {
                Some(Ok(Message::Data {
                    fd: messages::Fd::Stdin,
                    msg,
                })) => {
                    if write_half.write_all(&msg).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close {
                    fd: messages::Fd::Stdin,
                    ..
                })) => {
                    let _ = write_half.shutdown().await;
                }
                Some(Ok(_)) => {}
                None | Some(Err(_)) => break,
            }
        }
    });

    // The target closing (EOF on read_half) ends the session: reader_task has queued
    // Close{Stdout} and dropped its tx by the time this returns, so the writer below
    // sees the channel close on its own. No linger after that Close: CmdConnect is only
    // served host→guest, not over the guest→host bridge [`linger`] works around.
    copy_out.await?;
    client_stream_reader.abort();
    drop(client_stream_reader);
    writer.await?;
    debug!("connect [{req_id}] done");

    Ok(())
}

async fn reader_task<T: AsyncRead + Unpin>(
    req_id: usize,
    fd_kind: crate::messages::Fd,
    mut src: T,
    tx: mpsc::Sender<Message>,
) {
    let mut read_count = 0;
    let mut buf = [0u8; 4096];
    loop {
        match src.read(&mut buf).await {
            Ok(size) => {
                // info!("stdout read {}", size);
                if size == 0 {
                    let _ = tx
                        .send(Message::Close {
                            fd: fd_kind,
                            error: None,
                        })
                        .await;
                    break;
                }
                let data = &buf[0..size];
                match tx
                    .send(Message::Data {
                        fd: fd_kind,
                        msg: data.into(),
                    })
                    .await
                {
                    Ok(()) => {
                        read_count += size;
                        continue;
                    }
                    Err(e) => {
                        // normal when the client went away (the writer dropped rx)
                        debug!("command [{req_id}] send error {e}");
                        break;
                    }
                };
            }
            Err(e) => {
                error!("command [{req_id}] {fd_kind} read error {e}");
                let _ = tx
                    .send(Message::Close {
                        fd: fd_kind,
                        error: Some(e.to_string()),
                    })
                    .await;
                break;
            }
        }
    }
    drop(tx);
    debug!("command [{req_id}] done reading from {fd_kind} ({read_count} bytes)");
}

/// How long a new connection may take to send its request by default ([`Limits`]): a client
/// sends it at once, and an idle connection holds a task and a descriptor for nothing.
pub const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum wait for the client to close after the session's last message.
const CLIENT_CLOSE_GRACE: Duration = Duration::from_secs(2);

/// Wait up to [`CLIENT_CLOSE_GRACE`] for the client to close after the last message.
/// Closing first can lose undelivered data, including a guest's host-command exit status:
/// libkrun's guest→host vsock bridge can reset the guest's stream when the host end closes.
/// On hang-up, `process_event` in
/// third_party/libkrun/src/devices/src/virtio/vsock/unix_proxy/unix.rs
/// pushes a reset before reading the socket's remaining data.
async fn linger(
    mut stream: impl Stream<Item = Result<Message, std::io::Error>> + Unpin,
    sink: impl Sink<Message, Error = std::io::Error>,
) {
    let closed = async { while let Some(Ok(_)) = stream.next().await {} };
    if time::timeout(CLIENT_CLOSE_GRACE, closed).await.is_err() {
        debug!("client still connected after the session's last message, closing");
    }
    drop(sink);
}

/// Send `msg` as the session's last message, then [`linger`].
async fn send_last(
    stream: impl Stream<Item = Result<Message, std::io::Error>> + Unpin,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin,
    msg: Message,
) -> Result<(), std::io::Error> {
    sink.send(msg).await?;
    linger(stream, sink).await;
    Ok(())
}

/// Send what `rx` yields on `sink` until it ends or `sink` fails; give `sink` back.
async fn writer_task<S: Sink<Message, Error = std::io::Error> + Unpin + Send + 'static>(
    mut rx: mpsc::Receiver<Message>,
    mut sink: S,
    req_id: usize,
) -> S {
    let (mut written_stdout, mut written_stderr) = (0, 0);
    while let Some(msg) = rx.recv().await {
        match &msg {
            Message::Data {
                fd: crate::messages::Fd::Stdout,
                msg,
            } => written_stdout += &msg.len(),
            Message::Data {
                fd: crate::messages::Fd::Stderr,
                msg,
            } => written_stderr += &msg.len(),
            _ => (),
        }

        if let Err(e) = sink.send(msg).await {
            error!("command [{req_id}] error in network writer: {e}");
            break;
        }
    }
    debug!(
        "command [{req_id}] network writer done (stdout:{written_stdout}, stderr:{written_stderr})"
    );
    sink
}

#[cfg(test)]
mod tests {
    use super::{
        ExecWrapper, SessionUser, TaskState, VkRoute, Wrappers, apply_user, give_tty, glob_match,
        inactivity_check_period, resolve_gid, resolve_user, route, run_as, split_user_group,
        wrap_cmd,
    };
    use crate::messages::{CmdExec, RunMode};
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn split_user_group_forms() {
        assert_eq!(split_user_group("builder"), ("builder", None));
        assert_eq!(
            split_user_group("builder:builder"),
            ("builder", Some("builder"))
        );
        assert_eq!(split_user_group("1000:1000"), ("1000", Some("1000")));
        assert_eq!(split_user_group("builder:1000"), ("builder", Some("1000")));
        assert_eq!(split_user_group(":grp"), ("", Some("grp")));
    }

    #[test]
    fn resolve_user_handles_docker_forms() {
        // root exists everywhere: name and numeric, with and without an explicit group.
        for spec in ["root", "0"] {
            let ru = resolve_user(spec).expect(spec);
            assert_eq!((ru.uid, ru.gid), (0, 0), "spec {spec}");
        }
        // Explicit group overrides the primary gid and yields exactly that one group —
        // the regression: `user:group` / `uid:gid` used to be fed whole to getpwnam.
        for spec in ["root:0", "0:0"] {
            let ru = resolve_user(spec).expect(spec);
            assert_eq!((ru.uid, ru.gid), (0, 0), "spec {spec}");
            assert_eq!(ru.groups, vec![0], "spec {spec}");
        }
        // A bare numeric uid with no passwd entry: taken as-is, gid defaults to 0.
        let ru = resolve_user("4000000000").expect("numeric uid");
        assert_eq!((ru.uid, ru.gid), (4_000_000_000, 0));
        assert_eq!(ru.groups, vec![0]);
        // An explicit numeric group still applies to an entry-less uid.
        let ru = resolve_user("4000000000:4000000001").expect("uid:gid");
        assert_eq!((ru.uid, ru.gid), (4_000_000_000, 4_000_000_001));
        // A genuinely unknown user name still errors.
        assert!(resolve_user("nosuchuser-zzz").is_err());
    }

    #[test]
    fn apply_user_exports_login_name_not_the_group_spec() {
        use std::ffi::OsStr;
        use tokio::process::Command;
        let mut command = Command::new("true");
        let user = SessionUser {
            spec: "root:0".into(),
            resolved: resolve_user("root:0"),
        };
        apply_user(&mut command, &sample_cmd(), user);
        let std_cmd = command.as_std();
        let env_val = |key| {
            std_cmd
                .get_envs()
                .find(|(k, _)| *k == OsStr::new(key))
                .and_then(|(_, v)| v)
                .map(OsStr::to_owned)
        };
        // The `:group` half is dropped: USER/LOGNAME name the login user, not the spec.
        assert_eq!(env_val("USER"), Some(OsStr::new("root").to_owned()));
        assert_eq!(env_val("LOGNAME"), Some(OsStr::new("root").to_owned()));
    }

    /// Run as root only (the guest agent's case): a non-root caller keeps the slave as is.
    /// A tokio test: the pty master registers with the reactor.
    #[tokio::test]
    async fn give_tty_hands_the_slave_to_the_session_user() {
        use std::os::fd::AsRawFd;
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root");
            return;
        }
        let (_master, slave) = crate::pty::openpty(24, 80).unwrap();
        give_tty(&slave, 65534, 65534).unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(slave.as_raw_fd(), &mut st) }, 0);
        assert_eq!(st.st_uid, 65534);
        let want = match resolve_gid("tty") {
            Ok(gid) => (gid, 0o620),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (65534, 0o600),
            Err(e) => panic!("tty group: {e}"),
        };
        assert_eq!((st.st_gid, st.st_mode & 0o7777), want);
    }

    /// With no user or group database at all, as in a scratch image, a numeric uid still
    /// resolves and an unknown group is reported as such. The test runs itself again over
    /// an empty /etc in user and mount namespaces, and is skipped where it cannot.
    #[test]
    fn lookups_without_a_user_database() {
        const INNER: &str = "VK_TEST_EMPTY_ETC";
        if std::env::var_os(INNER).is_some() {
            let ru = resolve_user("12345").unwrap();
            assert_eq!((ru.uid, ru.gid, ru.groups), (12345, 0, vec![0]));
            let e = resolve_user("0:nosuchgrp").err().unwrap();
            assert!(e.to_string().contains("unknown group"), "{e}");
            return;
        }
        let unshare = |script: &str| {
            let mut command = std::process::Command::new("unshare");
            command.args(["--user", "--map-root-user", "--mount", "sh", "-c", script]);
            command
        };
        let usable = unshare("mount -t tmpfs none /etc")
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !usable {
            eprintln!("skipped: needs unshare and unprivileged user namespaces");
            return;
        }
        // The filter follows the module, so a rename cannot leave the inner run empty.
        let name = format!(
            "{}::lookups_without_a_user_database",
            module_path!().split_once("::").unwrap().1
        );
        let out = unshare(r#"mount -t tmpfs none /etc && exec "$@""#)
            .arg("sh")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &name])
            .env(INNER, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{}\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn run_as_prefers_the_override_and_treats_empty_as_keep_current() {
        let default = || Some("dev".to_string());
        // A named override wins over the guest default.
        assert_eq!(run_as(Some("nobody"), default()), Some("nobody".into()));
        // No override falls back to the guest default.
        assert_eq!(run_as(None, default()), Some("dev".into()));
        // An empty override suppresses the fallback instead of deferring to it —
        // the property vk-core/tests/exec.rs relies on to stay hermetic.
        assert_eq!(run_as(Some(""), default()), None);
        // Neither side set, and an empty default, both mean "keep the current user".
        assert_eq!(run_as(None, None), None);
        assert_eq!(run_as(None, Some(String::new())), None);
        // With no default to fall back to, the override still decides on its own.
        assert_eq!(run_as(Some("nobody"), None), Some("nobody".into()));
        assert_eq!(run_as(Some(""), None), None);
    }

    fn sample_cmd() -> CmdExec {
        CmdExec {
            name: "git".into(),
            args: vec!["status".into()],
            env: vec![],
            clear_env: false,
            mode: RunMode::Interactive,
            dir: Some("./sub".into()),
            tty: None,
            user: Some("root".into()),
        }
    }

    fn wrapper(extra_env_allow: Vec<String>) -> ExecWrapper {
        ExecWrapper::new(PathBuf::from("/run/host-dispatch"), extra_env_allow, vec![])
    }

    #[test]
    fn wrap_cmd_prepends_original_command_as_args() {
        let wrapped = wrap_cmd(sample_cmd(), &wrapper(vec![]));
        assert_eq!(wrapped.name, "/run/host-dispatch");
        // the requested command line becomes the wrapper's argv
        assert_eq!(wrapped.args, vec!["git", "status"]);
    }

    /// A command named exactly `vk` takes the `vk` route, in the foreground only; every other
    /// name, a path to a `vk` or a `vk` with other words around it included, takes the main
    /// wrapper as before. Without a `vk` route, or without wrappers, nothing changes.
    #[test]
    fn route_sends_only_a_command_named_vk_to_the_vk_route() {
        let vk_route = || VkRoute {
            path: PathBuf::from("/usr/bin/vk"),
            args: vec!["service-exec".into()],
            max_concurrent: std::num::NonZeroUsize::new(2),
        };
        let wrappers = Wrappers::new(
            PathBuf::from("/run/host-dispatch"),
            vec![],
            vec![],
            Some(vk_route()),
        );
        let named = |name: &str| CmdExec {
            name: name.into(),
            ..sample_cmd()
        };
        let path_of = |w: Option<&ExecWrapper>| w.map(|w| w.path.clone());
        let (w, limit, refused) = route(&named("vk"), Some(&wrappers), true);
        assert_eq!(path_of(w), Some(PathBuf::from("/usr/bin/vk")));
        assert_eq!(limit.map(|l| l.max), Some(2));
        assert!(refused.is_some_and(|m| m.contains("`vk`")), "{refused:?}");
        let (_, _, refused) = route(&named("vk"), Some(&wrappers), false);
        assert_eq!(
            refused,
            Some("background commands are refused on this channel")
        );
        for other in ["git", "/usr/bin/vk", "./vk", "vk ", "VK", ""] {
            let (w, limit, refused) = route(&named(other), Some(&wrappers), true);
            assert_eq!(
                path_of(w),
                Some(PathBuf::from("/run/host-dispatch")),
                "{other:?}"
            );
            assert!(limit.is_none(), "{other:?}");
            assert_eq!(refused, None, "{other:?}");
        }
        let main_only = Wrappers::new(PathBuf::from("/run/host-dispatch"), vec![], vec![], None);
        let (w, limit, refused) = route(&named("vk"), Some(&main_only), true);
        assert_eq!(path_of(w), Some(PathBuf::from("/run/host-dispatch")));
        assert!(limit.is_none());
        assert_eq!(refused, None);
        for allow_background in [true, false] {
            let (w, limit, refused) = route(&named("vk"), None, allow_background);
            assert!(w.is_none() && limit.is_none());
            assert_eq!(refused.is_none(), allow_background);
        }
    }

    /// The `vk` route lets through only the default client environment, whatever the main
    /// wrapper's allowlist says.
    #[test]
    fn the_vk_route_takes_only_the_default_environment() {
        let wrappers = Wrappers::new(
            PathBuf::from("/run/host-dispatch"),
            vec!["VIRTKIT_*".into(), "MYAPP_*".into()],
            vec![],
            Some(VkRoute {
                path: PathBuf::from("/usr/bin/vk"),
                args: vec![],
                max_concurrent: None,
            }),
        );
        let cmd = || CmdExec {
            env: vec![
                "VIRTKIT_BOOT_SPEC={}".into(),
                "MYAPP_TOKEN=abc".into(),
                "LANG=C".into(),
            ],
            ..sample_cmd()
        };
        let (vk, _) = wrappers.vk.as_ref().unwrap();
        assert_eq!(wrap_cmd(cmd(), vk).env, ["LANG=C", "VK_EXEC_DIR=./sub"]);
        assert_eq!(
            wrap_cmd(cmd(), &wrappers.main).env,
            [
                "VIRTKIT_BOOT_SPEC={}",
                "MYAPP_TOKEN=abc",
                "LANG=C",
                "VK_EXEC_DIR=./sub"
            ]
        );
    }

    /// Fixed wrapper arguments come first, so nothing the client sends lands before them.
    #[test]
    fn wrap_cmd_puts_the_wrapper_args_first() {
        let wrapper = ExecWrapper::new(
            PathBuf::from("/usr/bin/vk"),
            vec![],
            vec!["service-exec".into(), "/job".into(), "--".into()],
        );
        let mut cmd = sample_cmd();
        cmd.name = "--config=/x".into();
        let wrapped = wrap_cmd(cmd, &wrapper);
        assert_eq!(
            wrapped.args,
            ["service-exec", "/job", "--", "--config=/x", "status"]
        );
    }

    /// The client chooses neither who the wrapper runs as nor where: the user is the server's
    /// own (an empty one, which no default run user replaces), and the requested dir is
    /// only handed to the wrapper. Its TERM goes through only if allowlisted.
    #[test]
    fn wrap_cmd_drops_the_client_user_dir_and_term() {
        let with_tty = || CmdExec {
            tty: Some(crate::messages::Tty {
                term: Some("evil".into()),
                rows: 24,
                cols: 80,
                modes: vec![],
            }),
            ..sample_cmd()
        };
        let wrapped = wrap_cmd(with_tty(), &wrapper(vec![]));
        assert_eq!(wrapped.user.as_deref(), Some(""));
        assert_eq!(run_as(wrapped.user.as_deref(), Some("app".into())), None);
        assert_eq!(wrapped.dir, None);
        assert_eq!(wrapped.env, ["VK_EXEC_DIR=./sub"]);
        assert_eq!(wrapped.tty.as_ref().map(|t| t.term.clone()), Some(None));
        let wrapped = wrap_cmd(with_tty(), &wrapper(vec!["TERM".into()]));
        assert_eq!(wrapped.tty.and_then(|t| t.term).as_deref(), Some("evil"));
        let mut cmd = sample_cmd();
        cmd.dir = None;
        assert_eq!(wrap_cmd(cmd, &wrapper(vec![])).env, ["VK_EXEC_DIR="]);
    }

    #[test]
    fn wrap_cmd_filters_client_env_to_the_allowlist() {
        let mut cmd = sample_cmd();
        cmd.clear_env = true;
        cmd.env = vec![
            "LD_PRELOAD=/tmp/evil.so".into(), // injection vector: must be dropped
            "BASH_ENV=/tmp/rc".into(),        // ditto
            "LANG=en_US.UTF-8".into(),        // default allowlist
            "LC_ALL=C".into(),                // default allowlist glob LC_*
            "MYAPP_TOKEN=abc".into(),         // admin-allowed below
        ];
        let wrapped = wrap_cmd(cmd, &wrapper(vec!["MYAPP_*".into()]));
        assert_eq!(
            wrapped.env,
            vec![
                "LANG=en_US.UTF-8",
                "LC_ALL=C",
                "MYAPP_TOKEN=abc",
                "VK_EXEC_DIR=./sub"
            ],
        );
        // the client cannot clear the trusted server env the wrapper inherits
        assert!(!wrapped.clear_env);
    }

    #[test]
    fn glob_match_handles_wildcards() {
        assert!(glob_match("LC_*", "LC_ALL"));
        assert!(glob_match("LC_*", "LC_")); // `*` matches empty
        assert!(!glob_match("LC_*", "LANG"));
        assert!(glob_match("LANG", "LANG"));
        assert!(!glob_match("LANG", "LANGUAGE"));
        assert!(glob_match("MYAPP_?", "MYAPP_X"));
        assert!(!glob_match("MYAPP_?", "MYAPP_XY"));
    }

    #[test]
    fn busy_then_idle() {
        let mut state = TaskState::new();
        state.inc();
        assert!(!state.inactive(Duration::ZERO));
        state.dec(true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(state.inactive(Duration::from_millis(1)));
    }

    #[test]
    fn status_request_does_not_reset_the_idle_clock() {
        let mut state = TaskState::new();
        std::thread::sleep(Duration::from_millis(5));
        // a status request runs with update_last = false: the idle timestamp must
        // survive it (it used to be cleared for good, disabling the timeout)
        state.inc();
        state.dec(false);
        assert!(state.inactive(Duration::from_millis(1)));
    }

    #[test]
    fn status_finishing_after_exec_does_not_hide_its_activity() {
        let mut state = TaskState::new();
        // Age the initial timestamp well past the threshold asserted below, so the assert can
        // only pass if the exec's own activity replaced it.
        std::thread::sleep(Duration::from_millis(100));
        state.inc(); // exec
        state.inc(); // overlapping status probe
        state.dec(true);
        // The exec ended while the probe was still running, so its activity lands here.
        state.dec(false);
        assert!(!state.inactive(Duration::from_millis(50)));
    }

    #[test]
    fn an_exec_outliving_a_status_request_still_counts() {
        // The mirror of the case above: the probe finishes first, so the exec is the last
        // task to end. Neither order may lose the exec's activity.
        let mut state = TaskState::new();
        std::thread::sleep(Duration::from_millis(100));
        state.inc(); // exec
        state.inc(); // overlapping status probe
        state.dec(false);
        state.dec(true);
        assert!(!state.inactive(Duration::from_millis(50)));
    }

    #[test]
    fn inactivity_check_period_is_bounded_and_never_zero() {
        // A timeout shorter than the cap is checked at its own resolution.
        assert_eq!(
            inactivity_check_period(Some(Duration::from_secs(3))),
            Duration::from_secs(3)
        );
        assert_eq!(
            inactivity_check_period(Some(Duration::from_secs(1800))),
            Duration::from_secs(10)
        );
        // `time::interval` panics on a zero period, so neither no-timeout nor a zero one
        // may reach it.
        assert!(!inactivity_check_period(None).is_zero());
        assert!(!inactivity_check_period(Some(Duration::ZERO)).is_zero());
    }
}
