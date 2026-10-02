//! `vk-hub local`: the hub for the one machine it is started on, run by the person whose VMs
//! they are — the role virt-manager plays for libvirt. There is no enrollment and no node:
//! the VMs come from `vk workloads --watch`, a `vk` child of the hub's that prints the list
//! each time it changes, and what a VM's page shows of one beyond the list it reads by
//! running `vk` commands.
//!
//! **Why a child, not a library.** The list is `vk`'s to make — its registry, its locks, its
//! dev environments' state — and `vk-hub` is a separate binary that does not link `vk`. A
//! long-lived child keeps what is costly on its own cadence: it looks every couple of seconds,
//! which is a directory scan and a few small files, but measures what each VM holds — a walk
//! of every page table of every process — every half minute and as a VM appears. A command
//! run anew every few seconds would either measure every time or lose the readings it repeats
//! between measurements. The child's lines are the versioned [`WorkloadList`] of
//! `vk-hub-proto`, so the two binaries agree on the shape however they were built.
//!
//! **The name it is served under.** Browsers keep cookies apart by host, not by port, and a
//! developer's machine serves many things on loopback — the ports `vk dev` forwards among
//! them. The UI is served as `vk-<random>.localhost`, which Chromium and Firefox resolve to
//! loopback and whose cookies they keep off `localhost`, `127.0.0.1` and every other name.
//!
//! **A name for each start.** A cookie still reaches the same name on any port, and loopback
//! ports are anyone's. A name kept across starts would be learnt by whatever took the hub's
//! port while it was down, from the `Host` of the next request a browser sent there; that
//! program could then catch the cookie on another port under the same name, or — `.localhost`
//! being a secure context — leave a service worker on the hub's origin to answer in its place.
//! So the name and the port are drawn anew as the hub starts, and every session and unspent
//! sign-in link of the last run ends: the name reaches a browser only in a sign-in link, and
//! what was caught under an old one opens nothing. The port is bound on both `127.0.0.1` and
//! `::1` — Chromium tries `::1` first for a `.localhost` name, and Firefox falls back to it —
//! so nothing else listens under the name on the hub's own port, and a hub asked for a port
//! taken on either refuses to start.

use std::io::IsTerminal;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpListener;
use vk_hub_proto::{Workload, WorkloadList};

use crate::server::Hub;
use crate::store::{Db, Role};

/// The admin socket `vk-hub local login` reaches the running hub through, in its state dir.
pub const ADMIN_SOCKET: &str = "admin.sock";

/// How long the sign-in link printed at startup stays valid.
const STARTUP_LINK_TTL: Duration = Duration::from_secs(3600);

/// The longest line `vk workloads` may print: the list is bounded to 256 KiB, and its memory
/// figures add a few dozen bytes a workload.
const MAX_LINE: u64 = 1 << 20;

/// How long a failing `vk workloads` waits before it is started again, at most.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What `vk-hub local` was asked for.
pub struct Options {
    pub state_dir: Option<PathBuf>,
    /// `None`, or `Some(0)`, for one the system picks.
    pub port: Option<u16>,
    pub open_browser: bool,
    pub vk: Option<PathBuf>,
}

/// `$XDG_STATE_HOME/virtkit/hub-local`, else `~/.local/state/virtkit/hub-local`: apart from
/// any fleet hub's data, so the two never share a database.
pub fn state_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("virtkit/hub-local"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_STATE_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/state/virtkit/hub-local"))
}

/// The `vk` to run, as an absolute path, so every command the hub runs is the same binary
/// whatever its working directory: `asked`, else the one installed beside this `vk-hub`, as
/// `build.sh` ships them, else the first `vk` on PATH. A symlink is kept as it is, so a `vk`
/// updated in place behind one is the one run.
fn vk_binary(asked: Option<PathBuf>) -> Result<PathBuf> {
    let beside = || {
        std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.join("vk")))
            .filter(|vk| vk.is_file())
    };
    let vk = match asked.or_else(beside) {
        // A bare name is looked up as a shell would; a path is taken as it is.
        Some(vk) if vk.components().count() > 1 => vk,
        named => {
            let name = named.unwrap_or_else(|| PathBuf::from("vk"));
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .filter(|dir| dir.is_absolute())
                .map(|dir| dir.join(&name))
                .find(|vk| is_executable(vk))
                .with_context(|| {
                    format!(
                        "no {} on PATH; name the vk to run with --vk",
                        name.display()
                    )
                })?
        }
    };
    let vk = std::path::absolute(&vk).with_context(|| format!("resolving {}", vk.display()))?;
    if !is_executable(&vk) {
        bail!("{} is not an executable file", vk.display());
    }
    Ok(vk)
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The name the UI is served under, `vk-<16 hex digits>.localhost`, drawn anew on every start.
fn host_name() -> Result<String> {
    Ok(format!("vk-{}.localhost", crate::random_hex(8)?))
}

/// How many ports are drawn, at most, before one free on both loopback addresses is found.
const PORT_DRAWS: usize = 16;

/// Listen on the UI's port on `127.0.0.1` and `::1`: `asked`, else one the system picks.
/// Returns the port and its listeners — one alone where the host has no `::1`.
fn bind_port(asked: Option<u16>) -> Result<(u16, Vec<TcpListener>)> {
    match asked.filter(|&port| port != 0) {
        Some(port) => bind_loopback(port).map_err(|(addr, e)| {
            let in_use = e.kind() == std::io::ErrorKind::AddrInUse;
            let err = anyhow::Error::new(e).context(format!("binding {addr}"));
            if in_use {
                err.context(format!(
                    "port {port} is taken: by another vk-hub local, or by a program that could \
                     catch your session's cookie on it — stop it, or leave out --port"
                ))
            } else {
                err
            }
        }),
        None => draw_port(),
    }
}

/// A port the system picks that is free on both loopback addresses.
fn draw_port() -> Result<(u16, Vec<TcpListener>)> {
    let mut last = None;
    for _ in 0..PORT_DRAWS {
        match bind_loopback(0) {
            Ok(bound) => return Ok(bound),
            // Free on 127.0.0.1 and taken on ::1: draw again.
            Err((addr, e)) if e.kind() == std::io::ErrorKind::AddrInUse && addr.is_ipv6() => {
                last = Some((addr, e));
            }
            Err((addr, e)) => return Err(e).with_context(|| format!("binding {addr}")),
        }
    }
    let (addr, e) = last.context("no port drawn")?;
    Err(e).with_context(|| format!("binding {addr}, after {PORT_DRAWS} ports taken on ::1"))
}

/// Listen on `port` — or one the system picks, for `0` — on `127.0.0.1`, then on the same
/// port on `::1` unless the host has no `::1`. Fails with the address that could not be bound.
fn bind_loopback(port: u16) -> Result<(u16, Vec<TcpListener>), (SocketAddr, std::io::Error)> {
    let v4 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let first = crate::server::listen(v4).map_err(|e| (v4, e))?;
    let port = first.local_addr().map_err(|e| (v4, e))?.port();
    let v6 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port);
    match crate::server::listen(v6) {
        Ok(second) => Ok((port, vec![first, second])),
        // No IPv6, or no ::1: a browser has nothing to try there either.
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EADDRNOTAVAIL | libc::EAFNOSUPPORT)
            ) =>
        {
            Ok((port, vec![first]))
        }
        Err(e) => Err((v6, e)),
    }
}

/// What the UI shows of this machine: the latest list, and the `vk` that makes it.
pub struct Local {
    pub vk: PathBuf,
    listing: Mutex<Listing>,
}

/// The VMs as last listed, or why there is no list.
#[derive(Clone, Debug, PartialEq)]
pub enum Listing {
    /// `vk workloads` has not answered yet.
    Waiting,
    Listed(WorkloadList),
    /// `vk workloads` failed or ended; the hub starts it again.
    Failed(String),
}

impl Local {
    pub fn new(vk: PathBuf) -> Self {
        Local {
            vk,
            listing: Mutex::new(Listing::Waiting),
        }
    }

    /// The VMs as last listed.
    pub fn listing(&self) -> Listing {
        self.lock().clone()
    }

    /// Replace the listing, telling the pages when it changed.
    pub fn set_listing(&self, listing: Listing, hub: &Hub) {
        let changed = {
            let mut held = self.lock();
            let changed = *held != listing;
            *held = listing;
            changed
        };
        if changed {
            hub.touch();
        }
    }

    /// The workload listed as `id`, with what it holds.
    pub fn workload(&self, id: &str) -> Option<(Workload, Option<u64>)> {
        match &*self.lock() {
            Listing::Listed(list) => list
                .workloads
                .iter()
                .find(|w| w.id == id)
                .map(|w| (w.clone(), list.mem_bytes.get(id).copied())),
            _ => None,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Listing> {
        // Replaced whole: nothing half-written for a panic to leave behind.
        self.listing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The most of a command's stdout kept, from the end [`Keep`] says: a view shows it whole, and
/// what the views run prints well below it.
const MAX_STDOUT: usize = 256 * 1024;

/// The most of its stderr kept, from its end, where a command says why it failed.
const MAX_STDERR: usize = 64 * 1024;

/// How long its output is still read once it has ended, for what a process it left behind
/// holding the pipes still prints.
const DRAIN_GRACE: Duration = Duration::from_secs(1);

/// What a `vk` command printed, and how it ended.
pub struct Output {
    pub ok: bool,
    /// How it ended, as `exit status: 1` or `killed after 20s`, and whether its stdout was cut.
    pub status: String,
    /// Whether more of its stdout was printed than is kept.
    pub cut: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Which end of a command's stdout is kept past [`MAX_STDOUT`]: the start of a report, the
/// end of a log.
#[derive(Clone, Copy, Debug)]
pub enum Keep {
    Head,
    Tail,
}

impl Local {
    /// Run `vk` with `args`, its stdin closed, for at most `timeout`, in a process group of its
    /// own, killed whole once it ends — the command and whatever it started. [`MAX_STDOUT`] of
    /// its stdout is kept, from the end `stdout` says, and its stderr's last [`MAX_STDERR`],
    /// the rest read and dropped so it is never left blocked on a full pipe. What `vk` prints
    /// is the host's: a page shows it through [`crate::ui::html::Html::output`].
    pub async fn run(
        &self,
        args: &[&std::ffi::OsStr],
        timeout: Duration,
        stdout: Keep,
    ) -> Result<Output> {
        let mut child = tokio::process::Command::new(&self.vk)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // Its own group: killed with what it started, and out of reach of the signals a
            // terminal sends the hub's.
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("running {}", self.vk.display()))?;
        // Killed as this returns, or as the page waiting on it goes away: nothing the command
        // left behind outlives it.
        let group = child
            .id()
            .and_then(|pid| libc::pid_t::try_from(pid).ok())
            .map(GroupKill);
        let mut out_pipe = child.stdout.take().context("taking the child's stdout")?;
        let mut err_pipe = child.stderr.take().context("taking the child's stderr")?;
        let mut out = match stdout {
            Keep::Head => Kept::head(MAX_STDOUT),
            Keep::Tail => Kept::tail(MAX_STDOUT),
        };
        let mut err = Kept::tail(MAX_STDERR);
        let (status, cut_short) = {
            let reading = async {
                let (a, b) =
                    tokio::join!(pump(&mut out_pipe, &mut out), pump(&mut err_pipe, &mut err));
                a.and(b)
            };
            tokio::pin!(reading);
            let deadline = tokio::time::sleep(timeout);
            tokio::pin!(deadline);
            // Read as it runs, and waited for at once: its end is not its pipes' end, which a
            // process it left behind may hold for as long as it lives.
            let mut read = None;
            let status = loop {
                tokio::select! {
                    status = child.wait() => break Some(status.context("waiting for it")?),
                    r = &mut reading, if read.is_none() => read = Some(r),
                    () = &mut deadline => break None,
                }
            };
            if status.is_none() {
                if let Some(group) = &group {
                    group.kill();
                }
                let _ = tokio::time::timeout(DRAIN_GRACE, child.wait()).await;
            }
            if read.is_none() {
                read = tokio::time::timeout(DRAIN_GRACE, &mut reading).await.ok();
            }
            match read {
                Some(Err(e)) => return Err(e).context("reading its output"),
                Some(Ok(())) => (status, false),
                None => (status, true),
            }
        };
        drop(group);
        let ok = status.is_some_and(|s| s.success());
        let mut status = match status {
            Some(status) => status.to_string(),
            None => format!(
                "killed after {}",
                crate::human_duration(Duration::from_secs(timeout.as_secs()))
            ),
        };
        if cut_short {
            status.push_str(", its output cut short: a process it left running held it");
        }
        // Shown, never parsed: a byte that is not UTF-8 reads as a terminal would show it.
        let (stdout, cut) = out.into_text();
        if cut {
            status.push_str(&format!(" ({})", cut_note()));
        }
        Ok(Output {
            ok,
            status,
            cut,
            stdout,
            stderr: err.into_text().0,
        })
    }
}

/// What a command's [`Output::status`] adds when its stdout was cut.
pub fn cut_note() -> String {
    format!("output cut at {} KiB", MAX_STDOUT / 1024)
}

/// A process group, killed whole as this is dropped.
struct GroupKill(libc::pid_t);

impl GroupKill {
    fn kill(&self) {
        // SAFETY: a plain syscall. The ID is the group's for as long as any of it lives, and
        // one left empty is handed out again only once the kernel has cycled through the
        // others.
        unsafe { libc::kill(-self.0, libc::SIGKILL) };
    }
}

impl Drop for GroupKill {
    fn drop(&mut self) {
        self.kill();
    }
}

/// What is kept of a stream: its first bytes, or its last.
struct Kept {
    bytes: Vec<u8>,
    cap: usize,
    from_end: bool,
    /// Whether any byte was dropped.
    cut: bool,
}

impl Kept {
    fn head(cap: usize) -> Self {
        Kept {
            bytes: Vec::new(),
            cap,
            from_end: false,
            cut: false,
        }
    }

    fn tail(cap: usize) -> Self {
        Kept {
            bytes: Vec::new(),
            cap,
            from_end: true,
            cut: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        if self.from_end {
            self.bytes.extend_from_slice(chunk);
            // Cut down in bulk, so each byte is moved a bounded number of times.
            if self.bytes.len() > 2 * self.cap {
                self.bytes.drain(..self.bytes.len() - self.cap);
                self.cut = true;
            }
        } else {
            let room = self.cap.saturating_sub(self.bytes.len());
            self.cut |= chunk.len() > room;
            self.bytes
                .extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
    }

    /// What was kept, decoded lossily, and whether any of the stream was dropped. A cut
    /// through a character drops the rest of it rather than showing it as `U+FFFD`, and the
    /// text is at most the cap long, however many bytes decode to a wider `U+FFFD`.
    fn into_text(mut self) -> (String, bool) {
        if self.bytes.len() > self.cap {
            self.bytes.drain(..self.bytes.len() - self.cap);
            self.cut = true;
        }
        if self.cut {
            if self.from_end {
                let torn = self
                    .bytes
                    .iter()
                    .take(3)
                    .take_while(|&&b| continuation(b))
                    .count();
                self.bytes.drain(..torn);
            } else {
                let keep = self.bytes.len() - torn_end(&self.bytes);
                self.bytes.truncate(keep);
            }
        }
        let mut text = String::from_utf8_lossy(&self.bytes).into_owned();
        if text.len() > self.cap {
            self.cut = true;
            if self.from_end {
                let start = (text.len() - self.cap..text.len())
                    .find(|&i| text.is_char_boundary(i))
                    .unwrap_or(text.len());
                text.drain(..start);
            } else {
                let end = (0..=self.cap)
                    .rev()
                    .find(|&i| text.is_char_boundary(i))
                    .unwrap_or(0);
                text.truncate(end);
            }
        }
        (text, self.cut)
    }
}

/// Whether `b` continues a UTF-8 sequence rather than begins one.
fn continuation(b: u8) -> bool {
    b & 0xc0 == 0x80
}

/// How many bytes at the end of `bytes` begin a UTF-8 sequence they do not finish.
fn torn_end(bytes: &[u8]) -> usize {
    for (back, &b) in bytes.iter().rev().take(4).enumerate() {
        if !continuation(b) {
            let len = match b {
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf7 => 4,
                _ => 1,
            };
            return if len > back + 1 { back + 1 } else { 0 };
        }
    }
    0
}

/// Read `r` to its end into `kept`.
async fn pump(r: &mut (impl tokio::io::AsyncRead + Unpin), kept: &mut Kept) -> std::io::Result<()> {
    let mut buf = vec![0; 16 * 1024];
    loop {
        match r.read(&mut buf).await? {
            0 => return Ok(()),
            n => kept.push(&buf[..n]),
        }
    }
}

/// Keep `local`'s listing current from `vk workloads --watch` for as long as the hub runs,
/// starting it again, with a backoff, whenever it ends.
pub async fn watch(local: Arc<Local>, hub: Arc<Hub>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        let why = match follow(&local, &hub).await {
            Ok(()) => "ended".to_string(),
            Err(e) => format!("{e:#}"),
        };
        eprintln!("vk-hub: `{} workloads --watch`: {why}", local.vk.display());
        local.set_listing(Listing::Failed(why), &hub);
        if started.elapsed() > MAX_BACKOFF * 2 {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Run `vk workloads --watch` and take each list it prints, until it ends.
async fn follow(local: &Local, hub: &Hub) -> Result<()> {
    let mut child = tokio::process::Command::new(&local.vk)
        .args(["workloads", "--watch"])
        // Held open for as long as lists are wanted: its end is the child's signal to go,
        // even when it has nothing to print and so no write to fail.
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("running {}", local.vk.display()))?;
    let _stdin = child.stdin.take();
    let stdout = child.stdout.take().context("taking the child's stdout")?;
    let mut lines = BufReader::new(stdout);
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = (&mut lines)
            .take(MAX_LINE)
            .read_until(b'\n', &mut line)
            .await
            .context("reading its output")?;
        if n == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            bail!("it printed a line longer than {MAX_LINE} bytes");
        }
        let list = parse(&line)?;
        local.set_listing(Listing::Listed(list), hub);
    }
    let status = child.wait().await.context("waiting for it")?;
    bail!("it exited ({status})")
}

/// One line of `vk workloads`, refused when it is of a version this build cannot read.
fn parse(line: &[u8]) -> Result<WorkloadList> {
    #[derive(serde::Deserialize)]
    struct Version {
        version: u32,
    }
    let version: Version =
        serde_json::from_slice(line).context("it printed something other than a list")?;
    if version.version != vk_hub_proto::WORKLOADS_VERSION {
        bail!(
            "it prints list version {}, and this vk-hub reads version {} — run the vk built with \
             it (--vk)",
            version.version,
            vk_hub_proto::WORKLOADS_VERSION
        );
    }
    let mut list: WorkloadList =
        serde_json::from_slice(line).context("it printed a list this vk-hub cannot read")?;
    list.workloads.truncate(vk_hub_proto::MAX_WORKLOADS);
    Ok(list)
}

/// `vk-hub local`: serve this machine's VMs until the process ends.
pub async fn serve(opts: Options) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let state = match opts.state_dir {
        Some(dir) => dir,
        None => state_dir()?,
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&state)
        .with_context(|| format!("creating {}", state.display()))?;
    let vk = vk_binary(opts.vk)?;
    let name = host_name()?;
    // Opened first: a second hub on this state dir stops at its lock, before it binds.
    let db = Arc::new(Db::open(&state.join("hub.db"))?);
    let (port, listeners) = bind_port(opts.port)?;
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let actor = format!("uid {}", unsafe { libc::geteuid() });
    let now = crate::now_secs();
    end_access(&db, now)?;
    let origin = format!("http://{name}:{port}");
    let hub = Arc::new(Hub::new(db, origin.clone()));
    let admin = crate::admin::bind(&state.join(ADMIN_SOCKET))?;
    tokio::spawn(crate::admin::serve(admin, hub.clone()));
    eprintln!("vk-hub: running {}", vk.display());
    let local = Arc::new(Local::new(vk));
    tokio::spawn(watch(local.clone(), hub.clone()));

    let (token, _) = hub
        .db
        .create_login(Role::Operator, STARTUP_LINK_TTL, &actor, now)?;
    let link = format!("{origin}{}?t={token}", crate::ui::LOGIN_PATH);
    let page = state.join(OPEN_PAGE);
    // One left by a hub that did not live to remove it holds a spent link.
    let _ = std::fs::remove_file(&page);
    eprintln!(
        "vk-hub: serving this machine's VMs at {origin}/ on {} (state in {})",
        listeners
            .iter()
            .filter_map(|l| l.local_addr().ok())
            .map(|a| a.ip().to_string())
            .collect::<Vec<_>>()
            .join(" and "),
        state.display()
    );
    // The link is a credential: printed to a terminal, or where asked for with --no-browser,
    // but not into a log that keeps the hub's stderr.
    let print_link = !opts.open_browser || std::io::stderr().is_terminal();
    let hint = if print_link {
        ""
    } else {
        "; `vk-hub local login` prints a sign-in link"
    };
    let by_hand = if print_link {
        eprintln!(
            "vk-hub: sign in within {} with this single-use link; `vk-hub local login` prints \
             another:\n\n    {link}\n",
            crate::human_duration(STARTUP_LINK_TTL)
        );
        "the link above"
    } else {
        "one `vk-hub local login` prints"
    };
    if opts.open_browser && open_browser(&page, &link, hint) {
        eprintln!(
            "vk-hub: opening a sign-in link in the browser; one that cannot read {} — a snap's, \
             kept out of hidden directories — shows an error instead: open {by_hand} by hand.\n",
            page.display()
        );
        tokio::spawn(remove_later(page, OPEN_PAGE_LIFE));
    }
    let ui = Arc::new(crate::ui::Ui::new(hub, &origin, local));
    let mut served = tokio::task::JoinSet::new();
    for listener in listeners {
        served.spawn(crate::ui::serve(listener, ui.clone()));
    }
    // Each serves until the process ends; the first to stop ends the hub.
    match served.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(e).context("serving the UI"),
        None => bail!("nothing to serve on"),
    }
}

/// The page, in the state dir, that the browser is opened on.
const OPEN_PAGE: &str = "open.html";

/// How long that page is kept: long enough for a browser to start and read it, and short, as
/// it holds the link until the link is spent or expires.
const OPEN_PAGE_LIFE: Duration = Duration::from_secs(60);

/// Open `link` in the desktop's browser, as Jupyter does: through `page`, in the private state
/// directory, which moves on to it, so the token is never in a command line another local
/// user can read. Returns whether `xdg-open` was started; `hint`, said when it was not, says
/// where else a link comes from.
fn open_browser(page: &Path, link: &str, hint: &str) -> bool {
    if let Err(e) = vk_fs::write_atomic(page, open_page(link).as_bytes(), 0o600) {
        eprintln!(
            "vk-hub: not opening a browser: writing {}: {e:#}{hint}",
            page.display()
        );
        return false;
    }
    let spawned = std::process::Command::new("xdg-open")
        .arg(page)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn();
    match spawned {
        // Reaped off the runtime; its own failure is the browser's to report.
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
            true
        }
        Err(e) => {
            eprintln!("vk-hub: not opening a browser: running xdg-open: {e}{hint}");
            let _ = std::fs::remove_file(page);
            false
        }
    }
}

/// End every session and void every unspent sign-in link, as a hub starting does.
fn end_access(db: &Db, now: u64) -> Result<()> {
    db.end_ui_logins("vk-hub local", now)?;
    db.end_ui_sessions(None, "vk-hub local", now)?;
    Ok(())
}

async fn remove_later(path: PathBuf, after: Duration) {
    tokio::time::sleep(after).await;
    let _ = std::fs::remove_file(&path);
}

/// The page that moves on to `link`.
fn open_page(link: &str) -> String {
    let mut html = crate::ui::html::Html::new();
    html.raw(
        "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0; url=",
    )
    .text(link)
    .raw("\"><a href=\"")
    .text(link)
    .raw("\">Sign in to vk-hub local</a>");
    html.into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_drawn_for_each_start() {
        let name = host_name().unwrap();
        let hex = name
            .strip_prefix("vk-")
            .and_then(|rest| rest.strip_suffix(".localhost"))
            .unwrap();
        assert!(
            hex.len() == 16 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{name}"
        );
        assert_ne!(host_name().unwrap(), name);
    }

    fn scratch(what: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-hub-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Drawn, bound on both addresses where the host has `::1`, and an asked one refused
    /// rather than moved when either is taken.
    #[tokio::test]
    async fn a_port_is_bound_on_both_addresses_and_a_taken_one_refused() {
        let (port, listeners) = bind_port(None).unwrap();
        let has_v6 = listeners.len() == 2;
        let addrs: Vec<SocketAddr> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
        assert_eq!(addrs[0], SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        if has_v6 {
            assert_eq!(addrs[1], SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port));
        }

        // Taken by the hub itself: refused, naming the port.
        let err = format!("{:#}", bind_port(Some(port)).unwrap_err());
        assert!(err.contains(&format!("port {port} is taken")), "{err}");
        assert!(err.contains("127.0.0.1"), "{err}");
        drop(listeners);
        // Freed, it is bound as asked — unless a test running beside this one drew it meanwhile.
        if let Ok((again, listeners)) = bind_port(Some(port)) {
            assert_eq!(again, port);
            drop(listeners);
        }

        // Taken on ::1 alone, as a squatter would take it: refused too, and drawn around. A
        // port of its own rather than the one just freed, which a child forked meanwhile by a
        // test beside this one may hold until it execs.
        if has_v6 {
            let squatter =
                crate::server::listen(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)).unwrap();
            let port = squatter.local_addr().unwrap().port();
            let err = format!("{:#}", bind_port(Some(port)).unwrap_err());
            assert!(err.contains(&format!("port {port} is taken")), "{err}");
            assert!(err.contains("[::1]"), "{err}");
            let (drawn, listeners) = bind_port(Some(0)).unwrap();
            assert_ne!(drawn, port);
            assert_eq!(listeners.len(), 2);
            drop((squatter, listeners));
        }
    }

    /// A restart ends what the last run opened: a cookie or link caught while the hub was
    /// down opens nothing.
    #[test]
    fn a_restart_ends_every_session_and_link() {
        let db = Db::open_memory().unwrap();
        let ttl = Duration::from_secs(600);
        let (link, _) = db.create_login(Role::Operator, ttl, "uid 7", 1000).unwrap();
        let (secret, session) = db.redeem_login(&link, 1001).unwrap().unwrap();
        let (unspent, _) = db.create_login(Role::Operator, ttl, "uid 7", 1002).unwrap();
        assert!(db.ui_session(&secret, 1003).unwrap().is_some());
        end_access(&db, 1003).unwrap();
        assert!(db.ui_session(&secret, 1003).unwrap().is_none());
        assert!(db.redeem_login(&unspent, 1003).unwrap().is_none());
        let audit = db.audit_page(None, 10).unwrap();
        let events: Vec<&str> = audit.iter().map(|(_, row)| row.event.as_str()).collect();
        let ended = format!("vk-hub local ended ui session {} (operator)", session.id);
        assert!(events.contains(&ended.as_str()), "{events:?}");
        assert!(
            events.contains(&"vk-hub local voided 1 unspent sign-in link(s)"),
            "{events:?}"
        );
    }

    /// The page holds the link, escaped, readable by its owner alone, and goes once read.
    #[tokio::test]
    async fn the_browser_s_page_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("open");
        let page = dir.join(OPEN_PAGE);
        let link = "http://vk-0123456789abcdef.localhost:1234/login?t=a&b=\"c";
        vk_fs::write_atomic(&page, open_page(link).as_bytes(), 0o600).unwrap();
        let html = std::fs::read_to_string(&page).unwrap();
        assert!(html.contains("content=\"0; url=http://vk-0123456789abcdef.localhost:1234/login?t=a&amp;b=&quot;c\""), "{html}");
        assert!(!html.contains("b=\"c"), "{html}");
        let mode = std::fs::metadata(&page).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        remove_later(page.clone(), Duration::from_millis(10)).await;
        assert!(!page.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_vk_run_is_an_absolute_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("vk");
        let vk = dir.join("vk");
        std::fs::write(&vk, "#!/bin/sh\n").unwrap();
        assert!(vk_binary(Some(vk.clone())).is_err(), "not executable");
        std::fs::set_permissions(&vk, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(vk_binary(Some(vk.clone())).unwrap(), vk);
        // A path is taken as it is, made absolute; a bare name is looked up on PATH.
        let sh = vk_binary(Some(PathBuf::from("sh"))).unwrap();
        assert!(sh.is_absolute() && sh.ends_with("sh"), "{}", sh.display());
        assert!(vk_binary(Some(PathBuf::from("vk-hub-no-such-binary"))).is_err());
        assert!(vk_binary(Some(PathBuf::from("./vk-hub-no-such-binary"))).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `vk` that is the shell script `body`.
    fn fake_vk(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let vk = dir.join("vk");
        // Written by `cp`, not here: a file this process holds open for writing, as a child
        // another test forks meanwhile inherits it, cannot be run (ETXTBSY).
        let source = vk.with_extension("sh");
        std::fs::write(&source, format!("#!/bin/sh\n{body}\n")).unwrap();
        let copied = std::process::Command::new("cp")
            .arg(&source)
            .arg(&vk)
            .status();
        assert!(copied.unwrap().success());
        std::fs::set_permissions(&vk, std::fs::Permissions::from_mode(0o755)).unwrap();
        vk
    }

    fn alive(pid: i32) -> bool {
        // A zombie has ended; only its parent, gone, would reap it.
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|stat| !stat.rsplit(')').next().unwrap_or("").starts_with(" Z"))
    }

    /// The process a fake `vk` left running and named in `pid_file`, killed as this is dropped
    /// should the command under test have failed to, so a failing test leaves nothing behind.
    struct LeftBehind(PathBuf);

    impl LeftBehind {
        fn pid(&self) -> i32 {
            std::fs::read_to_string(&self.0)
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        }

        /// Whether it has ended, given a moment to.
        async fn ended(&self) -> bool {
            let pid = self.pid();
            for _ in 0..50 {
                if !alive(pid) {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            false
        }
    }

    impl Drop for LeftBehind {
        fn drop(&mut self) {
            if let Some(pid) = std::fs::read_to_string(&self.0)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                // SAFETY: a plain syscall on the test's own child's child.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }

    /// Past its time limit the command is killed with what it started, which held its pipes,
    /// and what it printed so far is kept.
    #[tokio::test]
    async fn a_command_past_its_time_is_killed_with_its_group() {
        let dir = scratch("group");
        let left = LeftBehind(dir.join("pid"));
        let vk = fake_vk(
            &dir,
            &format!(
                "sleep 600 & echo $! > '{}'\necho started\nsleep 600",
                left.0.display()
            ),
        );
        let local = Local::new(vk);
        let began = Instant::now();
        let out = local
            .run(&[], Duration::from_secs(1), Keep::Head)
            .await
            .unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{:?}",
            began.elapsed()
        );
        assert!(!out.ok);
        assert_eq!(out.status, "killed after 1s");
        assert_eq!(out.stdout, "started\n");
        assert!(
            left.ended().await,
            "pid {} outlived its group's kill",
            left.pid()
        );
        drop(left);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Its stderr's end is kept, where a failure says why, and its stdout's start, or its end
    /// when asked.
    #[tokio::test]
    async fn stderr_keeps_its_tail_and_stdout_the_end_asked_for() {
        let dir = scratch("tail");
        let vk = fake_vk(
            &dir,
            "echo first; i=0; while [ $i -lt 8000 ]; do \
             echo \"line $i of what came before the failure\"; \
             echo \"line $i of what came before the failure\" >&2; i=$((i+1)); done\n\
             echo last; echo 'the reason it failed' >&2\nexit 3",
        );
        let local = Local::new(vk);
        let out = local
            .run(&[], Duration::from_secs(30), Keep::Head)
            .await
            .unwrap();
        assert!(!out.ok);
        assert_eq!(out.status, "exit status: 3 (output cut at 256 KiB)");
        assert!(out.cut);
        assert!(
            out.stderr.ends_with("the reason it failed\n"),
            "{:?}",
            out.stderr.get(..80)
        );
        assert!(out.stderr.len() <= MAX_STDERR);
        assert!(out.stderr.len() > MAX_STDERR - 64);
        assert!(out.stdout.starts_with("first\n"));
        assert_eq!(out.stdout.len(), MAX_STDOUT);
        let out = local
            .run(&[], Duration::from_secs(30), Keep::Tail)
            .await
            .unwrap();
        assert!(out.cut);
        assert!(
            out.stdout.ends_with("failure\nlast\n"),
            "{:?}",
            out.stdout.get(..80)
        );
        assert_eq!(out.stdout.len(), MAX_STDOUT);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A command that ends while something it left running holds its pipes is waited for at
    /// its end, its output read for a moment longer, and what it left killed.
    #[tokio::test]
    async fn a_command_is_done_when_it_exits_not_when_its_pipes_close() {
        let dir = scratch("drain");
        let left = LeftBehind(dir.join("pid"));
        let vk = fake_vk(
            &dir,
            &format!("sleep 600 & echo $! > '{}'\necho done", left.0.display()),
        );
        let began = Instant::now();
        let out = Local::new(vk)
            .run(&[], Duration::from_secs(60), Keep::Head)
            .await
            .unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "{:?}",
            began.elapsed()
        );
        assert!(out.ok);
        assert!(
            out.status.contains("its output cut short"),
            "{}",
            out.status
        );
        assert!(!out.cut);
        assert_eq!(out.stdout, "done\n");
        assert!(
            left.ended().await,
            "pid {} outlived its command",
            left.pid()
        );
        drop(left);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn kept_bytes_are_bounded_at_either_end() {
        let mut head = Kept::head(4);
        let mut tail = Kept::tail(4);
        for chunk in [&b"ab"[..], b"cdef", b"", b"ghij"] {
            head.push(chunk);
            tail.push(chunk);
        }
        assert_eq!(head.into_text(), ("abcd".into(), true));
        assert_eq!(tail.into_text(), ("ghij".into(), true));
        let mut short = Kept::tail(4);
        short.push(b"xy");
        assert_eq!(short.into_text(), ("xy".into(), false));
        let mut exact = Kept::head(4);
        exact.push(b"wxyz");
        assert_eq!(exact.into_text(), ("wxyz".into(), false));
    }

    /// A cut through a character drops what is left of it, and bytes that are no UTF-8 still
    /// decode to no more than the cap.
    #[test]
    fn kept_text_is_cut_at_a_character() {
        // "é" is two bytes, "€" three: a cap of 4 cuts either.
        let mut head = Kept::head(4);
        head.push("aé€".as_bytes());
        assert_eq!(head.into_text(), ("aé".into(), true));
        let mut tail = Kept::tail(4);
        tail.push("€aé".as_bytes());
        assert_eq!(tail.into_text(), ("aé".into(), true));
        let mut tail = Kept::tail(4);
        tail.push("x€é".as_bytes());
        assert_eq!(tail.into_text(), ("é".into(), true));
        let mut bad = Kept::tail(4);
        bad.push(&[0xff; 4]);
        let (text, cut) = bad.into_text();
        assert_eq!((text.as_str(), cut), ("\u{fffd}", true));
        let mut whole = Kept::head(8);
        whole.push("é€".as_bytes());
        assert_eq!(whole.into_text(), ("é€".into(), false));
    }

    #[test]
    fn a_list_of_another_version_is_refused() {
        let list = parse(br#"{"version":1,"workloads":[]}"#).unwrap();
        assert!(list.workloads.is_empty());
        let err = parse(br#"{"version":2,"workloads":"changed"}"#).unwrap_err();
        assert!(format!("{err:#}").contains("version 2"), "{err:#}");
        assert!(parse(b"virtkit: oops").is_err());
    }

    /// A child that prints two lists and ends: both are taken, and its end is a failure the
    /// hub reports and starts it again over.
    #[tokio::test]
    async fn the_child_s_lists_are_followed_until_it_ends() {
        let dir = std::env::temp_dir().join(format!("vk-hub-follow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vk = dir.join("vk");
        std::fs::write(
            &vk,
            "#!/bin/sh\n[ \"$1 $2\" = 'workloads --watch' ] || exit 9\n\
             echo '{\"version\":1,\"workloads\":[],\"omitted\":3}'\n\
             echo '{\"version\":1,\"workloads\":[],\"omitted\":4}'\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&vk, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hub = Hub::new(
            Arc::new(Db::open_memory().unwrap()),
            "http://hub.example".into(),
        );
        let local = Local::new(vk);
        let changes = hub.subscribe();
        let err = follow(&local, &hub).await.unwrap_err();
        assert!(format!("{err:#}").contains("exited"), "{err:#}");
        assert!(changes.has_changed().unwrap());
        match local.listing() {
            Listing::Listed(list) => assert_eq!(list.omitted, 4),
            other => panic!("{other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
