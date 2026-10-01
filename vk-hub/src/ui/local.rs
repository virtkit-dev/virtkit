//! `vk-hub local`'s pages: this machine's VMs, and each one's own page, both kept live.
//!
//! A VM's ID is the one `vk workloads` derives from its state dir, sixteen hex digits, and the
//! only value of the host's that goes into a path or an attribute htmx reads; the router takes
//! nothing else for one.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hyper::{Response, StatusCode};
use tokio::sync::watch;
use vk_fleet_proto::{Workload, WorkloadKind};

use super::html::Html;
use super::pages::{self, dash, end_section, kv, kv_node, section};
use super::sse::{self, Source};
use super::{Auth, Body, Ui};
use crate::local::{Listing, Local};
use crate::server::Hub;
use crate::store::Role;

/// Start the task that renders the VMs table once for every page listing it.
pub(super) fn feed(hub: &Hub, local: &Arc<Local>) -> watch::Sender<Option<Bytes>> {
    sse::feed(hub.subscribe(), "vms", render_vms(local.clone()))
}

fn render_vms(local: Arc<Local>) -> sse::Render {
    Arc::new(move || Ok(vms_table(&local.listing(), crate::now_secs()).into_string()))
}

/// What `/events/<event>` streams, if it is one of local mode's.
pub(super) fn source(event: &str, ui: &Ui) -> Option<Source> {
    if event == "vms" {
        return Some(Source::Shared {
            name: "vms",
            feed: ui.vms_feed.subscribe(),
            render: render_vms(ui.local.clone()),
        });
    }
    let id = event
        .strip_prefix("vm/")
        .filter(|id| valid_id(id))?
        .to_string();
    let local = ui.local.clone();
    Some(Source::Own {
        name: "vm",
        changes: ui.hub.subscribe(),
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
        .filter(|name| super::actions::valid_dev_name(name))
        .map(|name| Target::Dev(name.to_string()))
}

/// The page for `path`, if it is one of local mode's.
pub(super) async fn get(path: &str, auth: &Auth, ui: &Ui) -> Option<Response<Body>> {
    let now = crate::now_secs();
    if path == "/" {
        return Some(super::page(list(auth, &ui.local.listing(), now)));
    }
    if path == "/dev" {
        return Some(super::actions::dev_page(auth, ui).await);
    }
    let id = path.strip_prefix("/vm/").filter(|id| valid_id(id))?;
    let Some((w, mem)) = ui.local.workload(id) else {
        return Some(super::message(
            StatusCode::NOT_FOUND,
            "No such VM is running on this machine.",
        ));
    };
    let views = views(&ui.local, &w).await;
    Some(super::page(vm(auth, id, &w, mem, &ui.local, &views)))
}

/// How long a view of a VM may take to read: a page waits on it.
const VIEW_TIMEOUT: Duration = Duration::from_secs(20);

/// How many of the console's last lines a VM's page shows.
const CONSOLE_LINES: &str = "100";

/// What a VM's page shows beside its live fragment, each read by the `vk` command a shell
/// would use: its console's tail, what atop recorded of it, what its switch recorded of its
/// egress.
struct Views {
    console: View,
    atop: View,
    egress: View,
}

enum View {
    Text(String),
    /// Nothing to show, and why, in the hub's words.
    None(&'static str),
    /// The command failed: how, and what it said.
    Failed(String),
}

async fn views(local: &Local, w: &Workload) -> Views {
    let dir = OsStr::new(&w.state_dir);
    let run = |args: Vec<&'static str>| {
        let mut all: Vec<&OsStr> = args.into_iter().map(OsStr::new).collect();
        all.push(dir);
        async move { view(local.run(&all, VIEW_TIMEOUT).await) }
    };
    // A VM records atop of itself only when booted to (`vk run --atop`, a CI job's
    // `[executor] atop`); asking `vk atop` of one that does not would attach a sampler.
    let recording = Path::new(&w.state_dir).join("atop/atop.log").is_file();
    let atop = async {
        if recording {
            run(vec!["atop", "--summary"]).await
        } else {
            View::None(
                "Not recording: a VM records itself when booted with `vk run --atop`, and \
                 `vk atop <dir>` attaches a sampler to one that does not.",
            )
        }
    };
    let egress = async {
        if w.kind == WorkloadKind::CiJob {
            match run(vec!["egress-report"]).await {
                View::Text(t) if t.trim().is_empty() => View::None("Nothing recorded."),
                v => v,
            }
        } else {
            View::None("Only a CI job's switch records its egress.")
        }
    };
    let (console, atop, egress) =
        tokio::join!(run(vec!["logs", "-n", CONSOLE_LINES]), atop, egress);
    Views {
        console,
        atop,
        egress,
    }
}

fn view(out: anyhow::Result<crate::local::Output>) -> View {
    match out {
        Ok(out) if out.ok => View::Text(out.stdout),
        Ok(out) => View::Failed(format!("{}: {}", out.status, out.stderr.trim())),
        Err(e) => View::Failed(format!("{e:#}")),
    }
}

/// Whether `id` is a VM's ID as `vk workloads` writes one: sixteen lowercase hex digits.
fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `/`: the VMs this machine runs.
fn list(auth: &Auth, listing: &Listing, now: u64) -> Html {
    let mut main = Html::new();
    main.raw("<h1>VMs on this machine</h1>")
        .raw("<div id=\"vms\" hx-ext=\"sse\" sse-connect=\"/events/vms\" sse-swap=\"vms\" ")
        .raw("sse-close=\"close\">")
        .html(&vms_table(listing, now))
        .raw("</div>");
    pages::layout("VMs", auth, &main)
}

/// The VMs as `vk workloads` last listed them, or why there is no list.
fn vms_table(listing: &Listing, now: u64) -> Html {
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
        let column = if column == "UP" { "STARTED" } else { column };
        h.raw("<th>").text(column).raw("</th>");
    }
    h.raw("</tr></thead><tbody>");
    for w in &list.workloads {
        let mem = list.mem_bytes.get(&w.id).copied();
        let mut cells = crate::workloads::cells(w, mem, now);
        // The page's own units for the figures; what a VM holds, which moves all the time, to
        // two figures, so the page changes only when it has moved.
        cells[5] = w.mem_reserved_mib.map_or_else(dash, pages::mib);
        cells[6] = mem.map_or_else(dash, pages::rough_bytes);
        cells[7] = w.started_at.map_or_else(dash, pages::started);
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

/// `/vm/<id>`: one VM. `id` goes into `sse-connect`: the router takes only hex for one.
fn vm(auth: &Auth, id: &str, w: &Workload, mem: Option<u64>, local: &Local, views: &Views) -> Html {
    let mut main = Html::new();
    main.raw("<h1>")
        .node(&crate::workloads::owner(w))
        .raw("</h1>");
    let ops = super::actions::vm_ops(w);
    let link = super::actions::vscode_link(w);
    if (auth.session.role >= Role::Operator && !ops.is_empty()) || link.is_some() {
        // Outside the live fragment, so an update never clears a form or the flash.
        main.raw("<section><div class=\"actions\">");
        if auth.session.role >= Role::Operator {
            let path = format!("/vm/{id}/action");
            for (op, label) in ops {
                super::actions::op_form(&mut main, auth, &path, op, label);
            }
        }
        if let Some(link) = &link {
            main.raw("<a href=\"")
                .text(link)
                .raw("\">open in VS Code</a><span class=\"sub\">through the SSH alias ")
                .raw("<code>vk dev ssh-config</code> prints, which your own SSH config must ")
                .raw("reach; <code>vk dev code</code> in the workspace needs none</span>");
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
            View::Text(text) => text_block(&mut main, text),
            View::None(why) => {
                main.raw("<p class=\"empty\">").text(why).raw("</p>");
            }
            View::Failed(why) => {
                main.raw("<p class=\"notes\">").node(why).raw("</p>");
            }
        }
        main.raw("</section>");
    }
    main.raw("<p class=\"sub\">The console, atop and egress are read as the page loads; ")
        .raw("<a href=\"/vm/")
        .text(id)
        .raw("\">reload</a> for newer.</p>");
    pages::layout(&crate::workloads::owner(w), auth, &main)
}

/// What a command printed, a line at a time, each made display-safe.
fn text_block(h: &mut Html, text: &str) {
    if text.trim().is_empty() {
        h.raw("<p class=\"empty\">nothing</p>");
        return;
    }
    h.raw("<pre>");
    for line in text.lines() {
        h.node(line).raw("\n");
    }
    h.raw("</pre>");
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
