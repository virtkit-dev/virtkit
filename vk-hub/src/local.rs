//! `vk-hub local`: the hub for the one machine it is started on, run by the person whose VMs
//! they are — the role virt-manager plays for libvirt. There is no enrollment and no node:
//! the VMs come from `vk workloads --watch`, a `vk` child of the hub's that prints the list
//! each time it changes, and what the UI does to them it does by running `vk` commands.
//!
//! **Why a child, not a library.** The list is `vk`'s to make — its registry, its locks, its
//! dev environments' state — and `vk-hub` is a separate binary that does not link `vk`. A
//! long-lived child keeps what is costly on its own cadence: it looks every couple of seconds,
//! which is a directory scan and a few small files, but measures what each VM holds — a walk
//! of every page table of every process — every half minute and as a VM appears. A command
//! run anew every few seconds would either measure every time or lose the readings it repeats
//! between measurements. The child's lines are the versioned [`WorkloadList`] of
//! `vk-fleet-proto`, so the two binaries agree on the shape however they were built.
//!
//! **The name it is served under.** Browsers keep cookies apart by host, not by port, and a
//! developer's machine serves many things on loopback — the ports `vk dev` forwards among
//! them. The UI is served as `vk-<random>.localhost`, which Chromium and Firefox resolve to
//! loopback and whose cookies they keep off `localhost`, `127.0.0.1` and every other name; the
//! name is drawn once and kept in the state directory, so a session survives a restart.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use vk_fleet_proto::{Workload, WorkloadList};

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
    pub port: u16,
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

/// The `vk` to run: the one installed beside this `vk-hub`, as `build.sh` ships them, else
/// whichever `vk` is on PATH.
fn vk_binary(asked: Option<PathBuf>) -> PathBuf {
    if let Some(vk) = asked {
        return vk;
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join("vk")))
        .filter(|vk| vk.is_file())
        .unwrap_or_else(|| PathBuf::from("vk"))
}

/// The name the UI is served under, `vk-<16 hex digits>.localhost`: drawn the first time and
/// kept in `<state_dir>/name`.
fn host_name(state_dir: &Path) -> Result<String> {
    let path = state_dir.join("name");
    match std::fs::read_to_string(&path) {
        Ok(text) if valid_host_name(text.trim()) => return Ok(text.trim().to_string()),
        Ok(_) => bail!(
            "{} does not hold a name of the form vk-<16 hex digits>.localhost; remove it to draw \
             a new one",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let name = format!("vk-{}.localhost", crate::random_hex(8)?);
    vk_fs::write_atomic(&path, format!("{name}\n").as_bytes(), 0o600)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(name)
}

fn valid_host_name(name: &str) -> bool {
    name.strip_prefix("vk-")
        .and_then(|rest| rest.strip_suffix(".localhost"))
        .is_some_and(|hex| {
            hex.len() == 16 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// What the UI shows of this machine: the latest list, the `vk` that makes it, and what the
/// UI has run.
pub struct Local {
    pub vk: PathBuf,
    listing: Mutex<Listing>,
    /// The last action on each thing acted on — a VM's state dir, a dev environment's name —
    /// under way or ended.
    actions: Mutex<HashMap<String, Action>>,
}

/// A `vk` command the UI ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// As a shell would show it: `vk stop /path`.
    pub command: String,
    /// The session's principal.
    pub by: String,
    pub started_at: u64,
    /// `None` while it runs.
    pub ended: Option<Ended>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ended {
    pub at: u64,
    pub ok: bool,
    /// How it ended, with the last line it printed.
    pub said: String,
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
            actions: Mutex::new(HashMap::new()),
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

    /// The last action on `key`.
    pub fn action(&self, key: &str) -> Option<Action> {
        self.lock_actions().get(key).cloned()
    }

    /// Run `vk args` in the background as `by`'s action on `key`, unless one is under way on
    /// it: started and ended in the audit log, and shown on the pages meanwhile. Returns the
    /// command as it is shown.
    pub fn start(
        self: &Arc<Self>,
        hub: &Arc<Hub>,
        key: &str,
        args: Vec<OsString>,
        timeout: Duration,
        by: &str,
    ) -> Result<String, &'static str> {
        let command = std::iter::once("vk".into())
            .chain(args.iter().map(|a| a.to_string_lossy().into_owned()))
            .collect::<Vec<String>>()
            .join(" ");
        {
            let mut actions = self.lock_actions();
            if actions.get(key).is_some_and(|a| a.ended.is_none()) {
                return Err(
                    "Refused: something is already being done to it; wait for that to end.",
                );
            }
            actions.insert(
                key.to_string(),
                Action {
                    command: command.clone(),
                    by: by.to_string(),
                    started_at: crate::now_secs(),
                    ended: None,
                },
            );
        }
        let (local, hub, key, by, shown) = (
            self.clone(),
            hub.clone(),
            key.to_string(),
            by.to_string(),
            command.clone(),
        );
        hub.touch();
        tokio::spawn(async move {
            audit(&hub, &by, format!("{by} ran `{shown}`")).await;
            let argv: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
            let (ok, said) = match local.run(&argv, timeout).await {
                Ok(out) => {
                    let last = |text: &str| {
                        text.lines()
                            .rev()
                            .map(str::trim)
                            .find(|l| !l.is_empty())
                            .map(str::to_string)
                    };
                    let said = last(&out.stderr)
                        .or_else(|| last(&out.stdout))
                        .map_or_else(|| out.status.clone(), |l| format!("{}: {l}", out.status));
                    (out.ok, said)
                }
                Err(e) => (false, format!("{e:#}")),
            };
            let event = format!(
                "`{shown}` {} ({said})",
                if ok { "succeeded" } else { "failed" }
            );
            audit(&hub, &by, event).await;
            if let Some(action) = local.lock_actions().get_mut(&key) {
                action.ended = Some(Ended {
                    at: crate::now_secs(),
                    ok,
                    said,
                });
            }
            hub.touch();
        });
        Ok(command)
    }

    fn lock_actions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Action>> {
        // Entries replaced whole: nothing half-written for a panic to leave behind.
        self.actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Listing> {
        // Replaced whole: nothing half-written for a panic to leave behind.
        self.listing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Write an audit line off the runtime; a failure to is logged, and the action goes on.
async fn audit(hub: &Arc<Hub>, actor: &str, event: String) {
    let (hub, actor) = (hub.clone(), actor.to_string());
    let written =
        tokio::task::spawn_blocking(move || hub.db.audit(&actor, &event, crate::now_secs())).await;
    match written {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("vk-hub: writing the audit log: {e:#}"),
        Err(e) => eprintln!("vk-hub: writing the audit log: {e}"),
    }
}

/// The most of a command's output kept: a page shows its tail.
const MAX_OUTPUT: u64 = 256 * 1024;

/// What a `vk` command printed, and how it ended.
pub struct Output {
    pub ok: bool,
    /// How it ended, as `exit status: 1` or the reason it was not waited for.
    pub status: String,
    pub stdout: String,
    pub stderr: String,
}

impl Local {
    /// Run `vk` with `args`, its stdin closed, for at most `timeout`; killed past it. Each
    /// stream's first [`MAX_OUTPUT`] bytes are kept. What `vk` prints is the host's: a page
    /// shows it through [`crate::ui::html::Html::node`].
    pub async fn run(&self, args: &[&OsStr], timeout: Duration) -> Result<Output> {
        let mut child = tokio::process::Command::new(&self.vk)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("running {}", self.vk.display()))?;
        let mut stdout = child.stdout.take().context("taking the child's stdout")?;
        let mut stderr = child.stderr.take().context("taking the child's stderr")?;
        let read = async {
            let (out, err) = tokio::join!(read_capped(&mut stdout), read_capped(&mut stderr));
            std::io::Result::Ok((out?, err?))
        };
        let ran = tokio::time::timeout(timeout, async {
            let (out, err) = read.await?;
            let status = child.wait().await?;
            std::io::Result::Ok((status, out, err))
        })
        .await;
        // Shown, never parsed: a byte that is not UTF-8 reads as a terminal would show it.
        Ok(match ran {
            Ok(Ok((status, out, err))) => Output {
                ok: status.success(),
                status: status.to_string(),
                stdout: String::from_utf8_lossy(&out).into_owned(),
                stderr: String::from_utf8_lossy(&err).into_owned(),
            },
            Ok(Err(e)) => return Err(e).context("reading its output"),
            Err(_) => Output {
                ok: false,
                status: format!(
                    "killed after {}",
                    crate::human_duration(Duration::from_secs(timeout.as_secs()))
                ),
                stdout: String::new(),
                stderr: String::new(),
            },
        })
    }
}

/// The first [`MAX_OUTPUT`] bytes `r` gives, and the rest read and dropped, so a writer is
/// never left blocked on a full pipe.
async fn read_capped(r: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    (&mut *r).take(MAX_OUTPUT).read_to_end(&mut kept).await?;
    tokio::io::copy(r, &mut tokio::io::sink()).await?;
    Ok(kept)
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
    if version.version != vk_fleet_proto::WORKLOADS_VERSION {
        bail!(
            "it prints list version {}, and this vk-hub reads version {} — run the vk built with \
             it (--vk)",
            version.version,
            vk_fleet_proto::WORKLOADS_VERSION
        );
    }
    let mut list: WorkloadList =
        serde_json::from_slice(line).context("it printed a list this vk-hub cannot read")?;
    list.workloads.truncate(vk_fleet_proto::MAX_WORKLOADS);
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
    let name = host_name(&state)?;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), opts.port);
    let listener = crate::server::listen(addr).with_context(|| format!("binding {addr}"))?;
    let port = listener
        .local_addr()
        .context("reading the bound port")?
        .port();
    let origin = format!("http://{name}:{port}");
    let db = Arc::new(Db::open(&state.join("hub.db"))?);
    let hub = Arc::new(Hub::new(db).with_ui_url(Some(origin.clone())));
    let admin = crate::admin::bind(&state.join(ADMIN_SOCKET))?;
    tokio::spawn(crate::admin::serve(admin, hub.clone()));
    let local = Arc::new(Local::new(vk_binary(opts.vk)));
    tokio::spawn(watch(local.clone(), hub.clone()));

    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let actor = format!("uid {}", unsafe { libc::geteuid() });
    let (token, _) =
        hub.db
            .create_login(Role::Operator, STARTUP_LINK_TTL, &actor, crate::now_secs())?;
    let link = format!("{origin}{}?t={token}", crate::ui::LOGIN_PATH);
    eprintln!(
        "vk-hub: serving this machine's VMs at {origin}/ (state in {})",
        state.display()
    );
    eprintln!(
        "vk-hub: sign in within {} with this single-use link; `vk-hub local login` prints \
         another:\n\n    {link}\n",
        crate::human_duration(STARTUP_LINK_TTL)
    );
    if opts.open_browser {
        open_browser(&state, &link);
    }
    let ui = Arc::new(crate::ui::Ui::local(hub, &origin, local));
    crate::ui::serve(listener, None, ui).await
}

/// Open `link` in the desktop's browser, as Jupyter does: through a page in the private state
/// directory that moves on to it, so the token is never in a command line another local user
/// can read. A browser that cannot read the page — a sandboxed one kept out of hidden
/// directories — leaves the printed link to be opened by hand.
fn open_browser(state: &Path, link: &str) {
    let page = state.join("open.html");
    let mut html = crate::ui::html::Html::new();
    html.raw(
        "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0; url=",
    )
    .text(link)
    .raw("\"><a href=\"")
    .text(link)
    .raw("\">Sign in to vk-hub local</a>");
    if let Err(e) = vk_fs::write_atomic(&page, html.into_string().as_bytes(), 0o600) {
        eprintln!(
            "vk-hub: not opening a browser: writing {}: {e:#}",
            page.display()
        );
        return;
    }
    let spawned = std::process::Command::new("xdg-open")
        .arg(&page)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn();
    match spawned {
        // Reaped off the runtime; its own failure is the browser's to report.
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
        }
        Err(e) => eprintln!("vk-hub: not opening a browser: running xdg-open: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_is_drawn_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("vk-hub-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let name = host_name(&dir).unwrap();
        assert!(valid_host_name(&name), "{name}");
        assert_eq!(host_name(&dir).unwrap(), name);
        std::fs::write(dir.join("name"), "localhost\n").unwrap();
        assert!(host_name(&dir).is_err());
        for bad in [
            "vk-0123456789abcdef.localhost.evil",
            "vk-0123456789ABCDEF.localhost",
            "vk-0123.localhost",
        ] {
            assert!(!valid_host_name(bad), "{bad}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
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
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()));
        let local = Local::new(vk);
        let mut changes = hub.subscribe();
        let err = follow(&local, &hub).await.unwrap_err();
        assert!(format!("{err:#}").contains("exited"), "{err:#}");
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        match local.listing() {
            Listing::Listed(list) => assert_eq!(list.omitted, 4),
            other => panic!("{other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
