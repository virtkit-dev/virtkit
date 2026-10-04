//! `vk-hub local`'s pages: this machine's VMs, and each one's own page, both kept live.
//!
//! A VM's ID is the one `vk workloads` derives from its state dir, sixteen hex digits, and the
//! only value of the host's that goes into a path or an attribute htmx reads; the router takes
//! nothing else for one.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::{Response, StatusCode};
use tokio::sync::watch;
use vk_hub_proto::{Workload, WorkloadKind};

use super::html::Html;
use super::pages::{self, dash, end_section, kv, kv_node, section};
use super::sse::{self, Source};
use super::{Auth, Body, Ui};
use crate::local::{Keep, Listing, Local};
use crate::server::Hub;
use crate::store::Role;

/// What local mode's pages read: this machine's VMs, and what the pages keep of them.
pub(super) struct LocalSite {
    pub(super) local: Arc<Local>,
    /// The VMs table, rendered once for every page listing it ([`sse::feed`]).
    pub(super) vms_feed: watch::Sender<Option<Bytes>>,
    /// What VM pages last read of their VMs.
    pub(super) views: ViewCache,
    /// What `/dev` last read.
    pub(super) dev_list: super::dev::DevList,
    /// The questions actions asked first, unanswered.
    pub(super) questions: super::actions::Questions,
}

impl LocalSite {
    pub(super) fn new(hub: &Hub, local: Arc<Local>) -> Self {
        LocalSite {
            vms_feed: feed(hub, &local),
            local,
            views: ViewCache::new(VIEWS_FRESH),
            dev_list: super::dev::DevList::new(),
            questions: super::actions::Questions::new(),
        }
    }
}

/// Local mode's navigation.
pub(super) const NAV: &str = "<a href=\"/\">VMs</a> <a href=\"/dev\">dev environments</a> \
                              <a href=\"/audit\">audit</a>";

/// The page around `main`, with local mode's navigation.
pub(super) fn layout(title: &str, auth: &Auth, main: &Html) -> Html {
    pages::frame(title, auth, NAV, main)
}

/// Start the task that renders the VMs table once for every page listing it.
fn feed(hub: &Hub, local: &Arc<Local>) -> watch::Sender<Option<Bytes>> {
    sse::feed(hub.subscribe(), "vms", render_vms(local.clone()))
}

fn render_vms(local: Arc<Local>) -> sse::Render {
    Arc::new(move || Ok(vms_table(&local.listing()).into_string()))
}

/// What `/events/<event>` streams, if it is one of local mode's.
pub(super) fn source(event: &str, hub: &Hub, site: &LocalSite) -> Option<Source> {
    if event == "vms" {
        return Some(Source::Shared {
            name: "vms",
            feed: site.vms_feed.subscribe(),
            render: render_vms(site.local.clone()),
        });
    }
    let id = event
        .strip_prefix("vm/")
        .filter(|id| valid_id(id))?
        .to_string();
    let local = site.local.clone();
    Some(Source::Own {
        name: "vm",
        changes: hub.subscribe(),
        render: Arc::new(move || {
            Ok(match local.workload(&id) {
                Some((w, mem)) => vm_detail(&w, mem, &local).into_string(),
                None => gone().into_string(),
            })
        }),
    })
}

/// What a `POST` acts on.
pub(super) enum Target {
    /// `/vm/<id>/action`
    Vm(String),
    /// `/dev/<name>/action`
    Dev(String),
}

/// What `path` acts on, if it is an action's, with its ID or name checked.
pub(super) fn action_target(path: &str) -> Option<Target> {
    let rest = path.strip_suffix("/action")?;
    if let Some(id) = rest.strip_prefix("/vm/").filter(|id| valid_id(id)) {
        return Some(Target::Vm(id.to_string()));
    }
    rest.strip_prefix("/dev/")
        .filter(|name| super::dev::valid_dev_name(name))
        .map(|name| Target::Dev(name.to_string()))
}

/// The page for `path`, if it is one of local mode's.
pub(super) async fn get(
    path: &str,
    auth: &Auth,
    ui: &Ui,
    site: &LocalSite,
) -> Option<Response<Body>> {
    if path == "/" {
        return Some(super::page(list(auth, &site.local.listing())));
    }
    if path == "/dev" {
        return Some(super::dev::page(auth, ui, site).await);
    }
    let id = path.strip_prefix("/vm/").filter(|id| valid_id(id))?;
    let Some((w, mem)) = site.local.workload(id) else {
        return Some(super::message(
            StatusCode::NOT_FOUND,
            "No such VM is running on this machine.",
        ));
    };
    let views = site.views.get(&site.local, &w).await;
    Some(super::page(vm(auth, id, &w, mem, &site.local, &views)))
}

/// How long a view of a VM may take to read: a page waits on it.
const VIEW_TIMEOUT: Duration = Duration::from_secs(20);

/// How many of the console's last lines a VM's page shows.
const CONSOLE_LINES: &str = "100";

/// Reuse a VM's views for this long so reloads and multiple tabs share command results.
pub(super) const VIEWS_FRESH: Duration = Duration::from_secs(5);

/// How many VM pages read their views at once, each with three `vk` commands.
const VIEW_READS: usize = 2;

/// How long a page waits for a read permit before reporting that it could not read.
const READ_WAIT: Duration = Duration::from_secs(10);

/// What VM pages last read, or are reading, by VM ID, and the permits that bound how many
/// `vk` commands their loads run at once.
pub(super) struct ViewCache {
    reads: tokio::sync::Semaphore,
    /// How long a read is shown again.
    fresh: Duration,
    kept: Mutex<HashMap<String, Arc<Slot>>>,
}

/// One VM's read, shared by requests that arrive before it completes.
type Slot = tokio::sync::OnceCell<Read>;

struct Read {
    /// When it ended; `None` for one that could not start, never shown again.
    at: Option<Instant>,
    views: Arc<Views>,
}

impl ViewCache {
    /// Cache completed reads for `fresh`.
    pub(super) fn new(fresh: Duration) -> Self {
        ViewCache {
            reads: tokio::sync::Semaphore::new(VIEW_READS),
            fresh,
            kept: Mutex::new(HashMap::new()),
        }
    }

    /// `w`'s views: read within the freshness window, or under way for another load, or read
    /// now once a permit is free.
    async fn get(&self, local: &Local, w: &Workload) -> Arc<Views> {
        let fresh = |r: &Read| r.at.is_some_and(|at| at.elapsed() < self.fresh);
        let slot = {
            let mut kept = self.lock();
            // What no load waits on and is no longer shown goes; a read a load gave up on is
            // taken up by the next.
            kept.retain(|_, slot| Arc::strong_count(slot) > 1 || slot.get().is_some_and(fresh));
            match kept.get(&w.id) {
                Some(slot) if slot.get().is_none_or(fresh) => slot.clone(),
                _ => {
                    let slot = Arc::new(Slot::new());
                    kept.insert(w.id.clone(), slot.clone());
                    slot
                }
            }
        };
        slot.get_or_init(|| self.read(local, w)).await.views.clone()
    }

    async fn read(&self, local: &Local, w: &Workload) -> Read {
        // Never closed: only the wait running out leaves a load without a permit.
        match tokio::time::timeout(READ_WAIT, self.reads.acquire()).await {
            Ok(Ok(_permit)) => {
                let views = views(local, w).await;
                Read {
                    at: Some(Instant::now()),
                    views: Arc::new(views),
                }
            }
            _ => {
                let why = "Not read: other pages are reading their VMs; reload in a moment.";
                Read {
                    at: None,
                    views: Arc::new(Views::none(why)),
                }
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Slot>>> {
        // Entries replaced whole: nothing half-written for a panic to leave behind.
        self.kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What a VM's page shows beside its live fragment, each read by the `vk` command a shell
/// would use: its console's tail, what atop recorded of it, what its switch recorded of its
/// egress.
struct Views {
    console: View,
    atop: View,
    egress: View,
}

impl Views {
    /// Nothing read, for `why`.
    fn none(why: &'static str) -> Self {
        Views {
            console: View::Absent(why),
            atop: View::Absent(why),
            egress: View::Absent(why),
        }
    }
}

enum View {
    /// What the command printed, and, when not all of it is kept, a note saying so.
    Text { text: String, note: Option<String> },
    /// Nothing to show, and why, in the hub's words.
    Absent(&'static str),
    /// The command failed: how, and what it said.
    Failed { how: String, said: String },
}

async fn views(local: &Local, w: &Workload) -> Views {
    let Some(dir) = exact_state_dir(w) else {
        return Views::none(
            "Not read: the listing cannot show this VM's state dir exactly; run `vk logs` on it \
             from a shell.",
        );
    };
    let run = |args: Vec<&'static str>, keep: Keep| {
        let mut all: Vec<&OsStr> = args.into_iter().map(OsStr::new).collect();
        all.extend([OsStr::new("--"), dir.as_os_str()]);
        async move { view(local.run(&all, VIEW_TIMEOUT, keep).await) }
    };
    let atop = async {
        let (kind, at) = (w.kind, dir.to_path_buf());
        match super::blocking(move || Ok(recording(kind, &at))).await {
            Ok(Ok(at)) => {
                let args = ["atop", "--summary", "--", &at].map(OsStr::new);
                view(local.run(&args, VIEW_TIMEOUT, Keep::Head).await)
            }
            Ok(Err(why)) => View::Absent(why),
            Err(e) => View::Failed {
                how: format!("{e:#}"),
                said: String::new(),
            },
        }
    };
    // What a CI job's switch refuses and the contacts it sees, and those a `vk run
    // --audit-egress` records in its state dir.
    let egress = async {
        match run(vec!["egress-report"], Keep::Head).await {
            View::Text { text, .. } if text.trim().is_empty() => View::Absent(
                "Nothing recorded: a CI job's switch records what it refuses and what the job \
                 contacts, and a `vk run --audit-egress` what its VM contacts.",
            ),
            v => v,
        }
    };
    let (console, atop, egress) = tokio::join!(
        run(vec!["logs", "--exact", "-n", CONSOLE_LINES], Keep::Tail),
        atop,
        egress
    );
    Views {
        console,
        atop,
        egress,
    }
}

/// The longest `atop.dir` read: a path, and its newline.
const ATOP_DIR_MAX: u64 = 4096;

/// The directory a VM of `kind` with state dir `dir` records atop of itself in, as `vk atop`
/// takes it — text — or why there is none to read. A VM records itself only when booted to
/// (`vk run --atop`, a CI job's `[executor] atop`), and asking `vk atop` of one that does not
/// would attach a sampler: the recording is in its state dir's `atop/`, or for a CI job in
/// the archive directory its job dir names in `atop.dir`. The log there is plain while the VM
/// runs and compressed once it has gone, and `vk atop` reads either. Blocking.
fn recording(kind: WorkloadKind, dir: &Path) -> Result<String, &'static str> {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    let at = match kind {
        WorkloadKind::CiJob => {
            let file = match std::fs::File::open(dir.join("atop.dir")) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err("Not recording: a CI job records itself when its runner's \
                                `[executor] atop` is set.");
                }
                Err(_) => return Err("Not read: its job dir's `atop.dir` cannot be read."),
            };
            let mut raw = Vec::new();
            if file.take(ATOP_DIR_MAX + 1).read_to_end(&mut raw).is_err() {
                return Err("Not read: its job dir's `atop.dir` cannot be read.");
            }
            if raw.len() as u64 > ATOP_DIR_MAX {
                return Err("Not read: its job dir's `atop.dir` is too long to be a path.");
            }
            let at = Path::new(OsStr::from_bytes(raw.strip_suffix(b"\n").unwrap_or(&raw)));
            if !at.is_absolute() {
                return Err("Not read: its job dir's `atop.dir` names no absolute path.");
            }
            at.to_path_buf()
        }
        _ => dir.join("atop"),
    };
    let Some(text) = at.to_str() else {
        return Err(
            "Not read: the archive its job dir names is not UTF-8, and `vk atop` takes text.",
        );
    };
    if !["atop.log", "atop.log.zst"]
        .iter()
        .any(|log| at.join(log).is_file())
    {
        return Err(match kind {
            WorkloadKind::CiJob => "Nothing recorded yet in the archive its job dir names.",
            _ => {
                "Not recording: a VM records itself when booted with `vk run --atop`, and \
                 `vk atop <dir>` attaches a sampler to one that does not."
            }
        });
    }
    Ok(text.to_string())
}

fn view(out: anyhow::Result<crate::local::Output>) -> View {
    match out {
        Ok(out) if out.ok => View::Text {
            note: out.cut.then(|| format!("({})", crate::local::cut_note())),
            text: out.stdout,
        },
        Ok(out) => View::Failed {
            how: out.status,
            said: out.stderr,
        },
        Err(e) => View::Failed {
            how: format!("{e:#}"),
            said: String::new(),
        },
    }
}

/// `w`'s state dir, when the list shows it as it is. `vk workloads` shows a path made fit to
/// display — lossily decoded, its control characters dropped — and derives the VM's ID from
/// the path's own bytes, so a shown path that hashes to the ID is the path. One that does not
/// is shown and never acted on or read: it would name another directory, or none.
pub(super) fn exact_state_dir(w: &Workload) -> Option<&Path> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(w.state_dir.as_bytes());
    (vk_hub_proto::to_hex(&digest[..8]) == w.id).then(|| Path::new(&w.state_dir))
}

/// Whether `id` is a VM's ID as `vk workloads` writes one: sixteen lowercase hex digits.
fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `/`: the VMs this machine runs.
fn list(auth: &Auth, listing: &Listing) -> Html {
    let mut main = Html::new();
    main.raw("<h1>VMs on this machine</h1>")
        .raw("<div id=\"vms\" hx-ext=\"sse\" sse-connect=\"/events/vms\" sse-swap=\"vms\" ")
        .raw("sse-close=\"close\">")
        .html(&vms_table(listing))
        .raw("</div>");
    layout("VMs", auth, &main)
}

/// The VMs as `vk workloads` last listed them, or why there is no list.
fn vms_table(listing: &Listing) -> Html {
    let mut h = Html::new();
    let list = match listing {
        Listing::Waiting => {
            h.raw("<p class=\"empty\">Asking <code>vk workloads</code> for the VMs…</p>");
            return h;
        }
        Listing::Failed(why) => {
            h.raw("<p class=\"notes\"><code>vk workloads</code> failed, and is run again: ")
                .node(why)
                .raw("</p>");
            return h;
        }
        Listing::Listed(list) => list,
    };
    if list.workloads.is_empty() && list.omitted == 0 {
        h.raw("<p class=\"empty\">No VM is running. <code>vk run</code>, <code>vk dev up</code> ")
            .raw("and CI jobs show up here as they start.</p>");
        return h;
    }
    h.raw("<table class=\"grid\"><thead><tr>");
    for column in crate::workloads::COLUMNS {
        h.raw("<th>").text(column).raw("</th>");
    }
    h.raw("</tr></thead><tbody>");
    for w in &list.workloads {
        let cells = cells(w, list.mem_bytes.get(&w.id).copied());
        h.raw("<tr>");
        for (i, cell) in cells.iter().enumerate() {
            h.raw("<td>");
            match i {
                // Of the hub's making: the kind's name and the figures.
                0 | 3..=7 => {
                    h.text(cell);
                }
                // The ID, leading to the VM's page; the router takes only hex for one.
                1 if valid_id(cell) => {
                    h.raw("<a href=\"/vm/")
                        .text(cell)
                        .raw("\"><code>")
                        .text(cell)
                        .raw("</code></a>");
                }
                1 => {
                    h.raw("<code>").node(cell).raw("</code>");
                }
                _ => {
                    h.node(cell);
                }
            }
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
    if list.omitted > 0 {
        h.raw("<p class=\"empty\">and ")
            .text(list.omitted)
            .raw(" more running, not listed</p>");
    }
    h
}

/// One workload's cells under [`crate::workloads::COLUMNS`], with what it holds now. What it
/// holds, which moves all the time, is to two figures, so the page changes only when it has
/// moved.
fn cells(w: &Workload, mem: Option<u64>) -> [String; 9] {
    [
        crate::workloads::kind_name(w.kind).to_string(),
        w.id.clone(),
        crate::workloads::owner(w),
        w.pid.map_or_else(dash, |p| p.to_string()),
        w.cpus.map_or_else(dash, |c| c.to_string()),
        w.mem_reserved_mib.map_or_else(dash, pages::mib),
        mem.map_or_else(dash, pages::rough_bytes),
        w.started_at.map_or_else(dash, pages::started),
        w.state_dir.clone(),
    ]
}

/// `/vm/<id>`: one VM. `id` goes into `sse-connect`: the router takes only hex for one.
fn vm(auth: &Auth, id: &str, w: &Workload, mem: Option<u64>, local: &Local, views: &Views) -> Html {
    let mut main = Html::new();
    main.raw("<h1>")
        .node(&crate::workloads::owner(w))
        .raw("</h1>");
    let ops = super::actions::vm_ops(w);
    if auth.session.role >= Role::Operator && !ops.is_empty() {
        // Outside the live fragment, so an update never clears a form or the flash.
        main.raw("<section><div class=\"actions\">");
        let path = format!("/vm/{id}/action");
        for (op, label) in ops {
            super::actions::op_form(&mut main, auth, &path, op, label);
        }
        main.raw("</div><div id=\"flash\"></div></section>");
    }
    main.raw("<div id=\"detail\" hx-ext=\"sse\" sse-connect=\"/events/vm/")
        .text(id)
        .raw("\" sse-swap=\"vm\" sse-close=\"close\">")
        .html(&vm_detail(w, mem, local))
        .raw("</div>");
    for (title, view) in [
        ("Console", &views.console),
        ("atop", &views.atop),
        ("Egress", &views.egress),
    ] {
        main.raw("<section><h2>").raw(title).raw("</h2>");
        match view {
            View::Text { text, note } => {
                text_block(&mut main, text);
                if let Some(note) = note {
                    main.raw("<p class=\"sub\">").node(note).raw("</p>");
                }
            }
            View::Absent(why) => {
                main.raw("<p class=\"empty\">").text(why).raw("</p>");
            }
            View::Failed { how, said } => {
                main.raw("<p class=\"notes\">").node(how).raw("</p>");
                if !said.trim().is_empty() {
                    text_block(&mut main, said);
                }
            }
        }
        main.raw("</section>");
    }
    main.raw("<p class=\"sub\">The console, atop and egress are read as the page loads; ")
        .raw("<a href=\"/vm/")
        .text(id)
        .raw("\">reload</a> for newer.</p>");
    layout(&crate::workloads::owner(w), auth, &main)
}

/// What a command printed, made [terminal-safe](Html::output).
fn text_block(h: &mut Html, text: &str) {
    if text.trim().is_empty() {
        h.raw("<p class=\"empty\">nothing</p>");
        return;
    }
    h.raw("<pre>").output(text).raw("</pre>");
}

/// A VM page's fragment once the VM has stopped.
fn gone() -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"empty\">This VM is no longer running.</p>");
    h
}

/// What the page shows of a VM below its name.
fn vm_detail(w: &Workload, mem: Option<u64>, local: &Local) -> Html {
    let mut h = Html::new();
    section(&mut h, "VM");
    kv(&mut h, "kind", crate::workloads::kind_name(w.kind));
    kv_node(&mut h, "state dir", &w.state_dir);
    for (key, value) in [
        ("image", &w.label),
        ("project", &w.project),
        ("job", &w.job_name),
        ("job ID", &w.job_id),
        ("workspace", &w.workspace),
        ("environment", &w.environment),
    ] {
        if let Some(value) = value {
            kv_node(&mut h, key, value);
        }
    }
    kv(
        &mut h,
        "managed by pid",
        &w.pid.map_or_else(dash, |p| p.to_string()),
    );
    kv(
        &mut h,
        "vCPUs",
        &w.cpus.map_or_else(dash, |c| c.to_string()),
    );
    kv(
        &mut h,
        "memory reserved",
        &w.mem_reserved_mib.map_or_else(dash, pages::mib),
    );
    kv(
        &mut h,
        "memory held",
        &mem.map_or_else(dash, pages::rough_bytes),
    );
    kv(
        &mut h,
        "started",
        &w.started_at.map_or_else(dash, pages::started),
    );
    h.raw("<tr><th>last action</th><td>");
    super::actions::action_line(&mut h, local.action(&super::actions::key(w)).as_ref());
    h.raw("</td></tr>");
    end_section(&mut h);
    h
}
