//! The fleet site for `vk-hub serve`: the nodes table, per-node inventory, load, workloads,
//! steering, commands and audit log. Operators steer nodes through the shared admin-socket
//! operations ([`crate::ops`]) as their session's principal. Monitoring-only nodes have no
//! steering controls.

use std::sync::Arc;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::{
    Acquisition, Operation, Outcome, RunnerMode, RunnerState, SpeedClass, StorageRole,
};

use super::html::Html;
use super::pages::{
    self, bytes, count, dash, end_section, kv, kv_node, mib, rough_bytes, rough_count, section,
    started,
};
use super::sse::{self, Source};
use super::{Auth, Body, Ui, actions, blocking, decode_form, field, message, page};
use crate::ops::{self, NodeView};
use crate::server::{HEARTBEAT, Hub};
use crate::store::{CommandRow, MonitoringOnly, NodeRow, NotEnrolled, Role};

/// A node page's latest commands.
const NODE_COMMANDS: usize = 20;

/// What the fleet's pages keep: the nodes table, rendered once for every page listing it
/// ([`sse::feed`]).
pub(super) struct FleetSite {
    nodes_feed: tokio::sync::watch::Sender<Option<bytes::Bytes>>,
}

impl FleetSite {
    pub(super) fn new(hub: &Arc<Hub>) -> Self {
        FleetSite {
            nodes_feed: sse::feed(hub.subscribe(), "nodes", render_nodes(hub.clone())),
        }
    }
}

/// The event `/events/<event>` swaps its fragment in on, if it is one of the fleet's.
pub(super) fn event_name(event: &str) -> Option<&'static str> {
    match event {
        "nodes" => Some("nodes"),
        _ => event
            .strip_prefix("node/")
            .filter(|id| vk_hub_proto::valid_id(id))
            .map(|_| "node"),
    }
}

/// What `/events/<event>` streams, if it is one of the fleet's.
pub(super) fn source(event: &str, hub: &Arc<Hub>, site: &FleetSite) -> Option<Source> {
    if event == "nodes" {
        return Some(Source::Shared {
            name: "nodes",
            feed: site.nodes_feed.subscribe(),
            render: render_nodes(hub.clone()),
        });
    }
    let id = event
        .strip_prefix("node/")
        .filter(|id| vk_hub_proto::valid_id(id))?
        .to_string();
    let hub = hub.clone();
    Some(Source::Own {
        name: "node",
        changes: hub.subscribe_node(&id),
        render: Arc::new(move || render_node(&hub, &id)),
    })
}

/// The page for `path`, if it is one of the fleet's: read-only, for any session.
pub(super) async fn get(
    path: &str,
    query: Option<&str>,
    auth: &Auth,
    ui: &Ui,
) -> Result<Option<Response<Body>>> {
    let hub = ui.hub.clone();
    let now = crate::now_secs();
    if path == "/" {
        let views = blocking(move || crate::ops::node_views(&hub)).await?;
        return Ok(Some(page(nodes(auth, &views, now))));
    }
    if path == "/audit" {
        let query = decode_form(query.unwrap_or("").as_bytes());
        let node = field(&query, "node")
            .filter(|n| vk_hub_proto::valid_id(n))
            .map(str::to_string);
        let before = field(&query, "before").and_then(|b| b.parse().ok());
        let (audit, names) = blocking(move || {
            let rows = hub
                .db
                .audit_page(node.as_deref(), before, pages::AUDIT_PAGE)?;
            let names = hub.db.node_names()?;
            anyhow::Ok((pages::AuditPage { node, rows }, names))
        })
        .await?;
        return Ok(Some(page(pages::audit(auth, &audit, Some(&names), NAV))));
    }
    if let Some(id) = path.strip_prefix("/node/")
        && vk_hub_proto::valid_id(id)
    {
        let id = id.to_string();
        let detail = blocking(move || read_node(&hub, &id)).await?;
        return Ok(Some(match detail {
            Some(detail) => page(node(auth, &detail, now)),
            None => message(StatusCode::NOT_FOUND, "There is no such node."),
        }));
    }
    Ok(None)
}

/// The nodes table, as one rendering for every nodes page.
fn render_nodes(hub: Arc<Hub>) -> sse::Render {
    Arc::new(move || {
        let nodes = crate::ops::node_views(&hub)?;
        Ok(nodes_table(&nodes, crate::now_secs()).into_string())
    })
}

/// Node `id`'s page fragment, or the line saying it has gone.
fn render_node(hub: &Hub, id: &str) -> Result<String> {
    Ok(match read_node(hub, id)? {
        Some(detail) => node_detail(&detail, crate::now_secs()).into_string(),
        None => gone().into_string(),
    })
}

/// What the node page shows of node `id`, or `None` for no such node.
fn read_node(hub: &Hub, id: &str) -> Result<Option<NodeDetail>> {
    let Some((row, workloads)) = hub.db.node_with_workloads(id)? else {
        return Ok(None);
    };
    let mut commands = hub.db.node_commands(id)?;
    commands.reverse();
    commands.truncate(NODE_COMMANDS);
    Ok(Some(NodeDetail {
        view: crate::ops::node_view(hub, id.to_string(), &row),
        workloads,
        commands,
        row,
    }))
}

/// What a node's page shows.
struct NodeDetail {
    view: NodeView,
    row: NodeRow,
    /// `None` until the node has listed any.
    workloads: Option<crate::store::Workloads>,
    /// The latest, newest first.
    commands: Vec<CommandRow>,
}

/// `/node/<id>/action`'s node, if `path` is that for a well-formed ID.
pub(super) fn action_node(path: &str) -> Option<&str> {
    path.strip_prefix("/node/")?
        .strip_suffix("/action")
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// What an operator asks of a node.
enum Steer {
    Ceiling(Option<u32>),
    Acquisition(Acquisition),
    Command(Operation),
}

/// The actions a node's page offers beside setting a ceiling, as `(op, label)`.
const NODE_OPS: [(&str, &str); 7] = [
    ("lift-ceiling", "lift ceiling"),
    ("stop", "stop acquisition"),
    ("resume", "resume acquisition"),
    ("drain", "drain"),
    ("undrain", "undrain"),
    ("quarantine", "quarantine"),
    ("release", "release"),
];

/// What `form` asks, or why it is no action.
fn steer(form: &[(String, String)]) -> Result<Steer, &'static str> {
    Ok(match field(form, "op").unwrap_or("") {
        "ceiling" => match field(form, "ceiling").map(|c| c.trim().parse::<u32>()) {
            Some(Ok(n)) if n > 0 => Steer::Ceiling(Some(n)),
            _ => {
                return Err(
                    "Refused: a ceiling is a number of jobs, at least 1. To take none, \
                     stop acquisition.",
                );
            }
        },
        "lift-ceiling" => Steer::Ceiling(None),
        "stop" => Steer::Acquisition(Acquisition::Stop),
        "resume" => Steer::Acquisition(Acquisition::Run),
        "drain" => Steer::Command(Operation::Drain),
        "undrain" => Steer::Command(Operation::Undrain),
        "quarantine" => Steer::Command(Operation::Quarantine),
        "release" => Steer::Command(Operation::Release),
        _ => return Err("No such action."),
    })
}

/// `POST /node/<id>/action`: run the shared admin-socket operation as the operator's session
/// principal. For htmx, return a status line while the node's fragment updates live.
/// For plain forms, redirect to the node's page or show the refusal.
pub(super) async fn node_action(
    req: Request<Incoming>,
    ui: &Ui,
    id: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let steer = match steer(&form) {
        Ok(steer) => steer,
        Err(why) => return Ok(actions::refused(htmx, StatusCode::BAD_REQUEST, why)),
    };
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    let node = id.to_string();
    let done = blocking(move || {
        let desired = |d: Option<vk_hub_proto::DesiredState>| match d {
            Some(d) => format!(
                "The hub now asks generation {}: ceiling {}, acquisition {}.",
                d.generation,
                pages::count(d.ceiling),
                crate::acquisition_name(d.acquisition)
            ),
            None => "Already so; nothing changed.".to_string(),
        };
        Ok(match steer {
            Steer::Ceiling(ceiling) => {
                ops::set_ceiling(&hub, &principal, &node, ceiling).map(desired)
            }
            Steer::Acquisition(a) => ops::set_acquisition(&hub, &principal, &node, a).map(desired),
            Steer::Command(op) => ops::command(&hub, &principal, &node, op).map(|c| {
                format!(
                    "Issued {} (command {}); what the node makes of it shows below.",
                    crate::store::operation_name(&c.op),
                    c.id
                )
            }),
        })
    })
    .await?;
    let said = match done {
        Ok(said) => said,
        Err(e) if e.is::<MonitoringOnly>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {e:#}."),
            ));
        }
        Err(e) if e.is::<NotEnrolled>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::NOT_FOUND,
                "There is no such node.",
            ));
        }
        Err(e) => return Err(e),
    };
    if !htmx {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::SEE_OTHER;
        // The node's ID: the router took it as hex.
        resp.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&format!("/node/{id}"))?,
        );
        return Ok(resp);
    }
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">")
        .text(said)
        .raw("</div>");
    Ok(actions::swap_none(super::html_response(StatusCode::OK, h)))
}

/// The page around `main`, with the fleet's navigation.
fn layout(title: &str, auth: &Auth, main: &Html) -> Html {
    pages::frame(title, auth, NAV, main)
}

/// The fleet's navigation.
pub(super) const NAV: &str = "<a href=\"/\">nodes</a> <a href=\"/audit\">audit</a>";

/// `/`: the nodes table.
fn nodes(auth: &Auth, nodes: &[NodeView], now: u64) -> Html {
    let mut main = Html::new();
    main.raw("<h1>Nodes</h1>")
        .raw("<div id=\"nodes\" hx-ext=\"sse\" sse-connect=\"/events/nodes\" sse-swap=\"nodes\" sse-close=\"close\">")
        .html(&nodes_table(nodes, now))
        .raw("</div>");
    layout("nodes", auth, &main)
}

// Where the pages put cells of their own, by column of `vk-hub nodes` and of a node's
// workloads; checked against the columns' names, so a reordering fails to build.
const NODE_ID: usize = 0;
const NODE_NAME: usize = 1;
const NODE_SYNC: usize = 7;
const NODE_LAST_SEEN: usize = 8;
const NODE_VK: usize = 9;
const VM_KIND: usize = 0;
const VM_ID: usize = 1;
const VM_PID: usize = 3;
const VM_RESERVED: usize = 5;
const VM_IN_USE: usize = 6;
const VM_STARTED: usize = 7;
const _: () = {
    let nodes = &crate::NODE_COLUMNS;
    assert!(column_is(nodes, NODE_ID, "ID") && column_is(nodes, NODE_NAME, "NAME"));
    assert!(column_is(nodes, NODE_SYNC, "SYNC"));
    assert!(column_is(nodes, NODE_LAST_SEEN, "LAST SEEN") && column_is(nodes, NODE_VK, "VK"));
    let vms = &crate::workloads::COLUMNS;
    assert!(column_is(vms, VM_KIND, "KIND") && column_is(vms, VM_ID, "ID"));
    assert!(column_is(vms, VM_PID, "PID") && column_is(vms, 4, "CPUS"));
    assert!(column_is(vms, VM_RESERVED, "RESERVED") && column_is(vms, VM_IN_USE, "IN USE"));
    assert!(column_is(vms, VM_STARTED, "STARTED"));
};

/// Whether `columns[i]` is `name`, at compile time.
const fn column_is(columns: &[&str], i: usize, name: &str) -> bool {
    if i >= columns.len() {
        return false;
    }
    let (a, b) = (columns[i].as_bytes(), name.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut k = 0;
    while k < a.len() {
        if a[k] != b[k] {
            return false;
        }
        k += 1;
    }
    true
}

/// The nodes table, with the columns of `vk-hub nodes`.
fn nodes_table(nodes: &[NodeView], now: u64) -> Html {
    let mut h = Html::new();
    if nodes.is_empty() {
        h.raw("<p class=\"empty\">No node has enrolled yet: <code>vk-hub token create</code> ")
            .raw("issues a token for <code>vk node join</code>.</p>");
        return h;
    }
    h.raw("<table class=\"grid\"><thead><tr>");
    for column in crate::NODE_COLUMNS {
        h.raw("<th>").text(column).raw("</th>");
    }
    h.raw("</tr></thead><tbody>");
    for n in nodes {
        let mut cells = crate::node_cells(n, now);
        // LAST SEEN, in the page's steps rather than the CLI's seconds.
        cells[NODE_LAST_SEEN] = n
            .last_seen
            .map_or_else(|| "never".to_string(), |t| age(now, t));
        h.raw("<tr class=\"")
            .raw(if n.connected { "up" } else { "down" })
            .raw("\">");
        for (i, cell) in cells.iter().enumerate() {
            h.raw("<td>");
            match i {
                // The ID, short, and the name, both leading to the node's page; the ID is
                // one the hub issued and the router checks as hex.
                NODE_ID | NODE_NAME => {
                    h.raw("<a href=\"/node/").text(&n.id).raw("\">");
                    if i == NODE_ID {
                        h.text(n.id.get(..8).unwrap_or(&n.id));
                    } else {
                        h.node(cell);
                    }
                    h.raw("</a>");
                }
                // What the node sent: its version.
                NODE_VK => {
                    h.node(cell);
                }
                _ => {
                    h.text(cell);
                }
            }
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
    h
}

/// `/node/<id>`.
///
/// The node's ID goes into `sse-connect` and the forms' paths: it is one the hub issued, and
/// the router takes only hex for one.
fn node(auth: &Auth, detail: &NodeDetail, now: u64) -> Html {
    let id = &detail.view.id;
    let mut main = Html::new();
    main.raw("<h1>").node(&detail.view.hostname).raw("</h1>");
    if auth.session.role >= Role::Operator && !detail.view.monitoring_only() {
        steer_forms(&mut main, auth, id);
    }
    main.raw("<div id=\"detail\" hx-ext=\"sse\" sse-connect=\"/events/node/")
        .text(id)
        .raw("\" sse-swap=\"node\" sse-close=\"close\">")
        .html(&node_detail(detail, now))
        .raw("</div>");
    layout(&detail.view.hostname, auth, &main)
}

/// An operator's forms, outside the live fragment so an update never clears one being filled
/// in or the flash. Each posts by htmx, and works as a plain form too.
fn steer_forms(h: &mut Html, auth: &Auth, id: &str) {
    let path = format!("/node/{id}/action");
    h.raw("<section><h2>Steer</h2><div class=\"actions\"><form method=\"post\" action=\"")
        .text(&path)
        .raw("\" hx-post=\"")
        .text(&path)
        .raw("\" hx-swap=\"none\">");
    pages::csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"ceiling\">")
        .raw("<input type=\"number\" name=\"ceiling\" min=\"1\" required aria-label=\"ceiling\">")
        .raw("<button>set ceiling</button></form>");
    for (op, label) in NODE_OPS {
        actions::op_form(h, auth, &path, op, label);
    }
    h.raw("</div><div id=\"flash\"></div></section>");
}

/// How long before `now` the instant `then` was, in steps of a heartbeat under a minute:
/// what a page shows moves only when it has something to say, not every second.
fn age(now: u64, then: u64) -> String {
    let step = HEARTBEAT.as_secs().max(1);
    let secs = now.saturating_sub(then);
    match secs {
        _ if secs < step => "just now".to_string(),
        0..60 => format!("{}s ago", secs / step * step),
        _ => format!("{} ago", crate::human_duration(crate::ago(now, then))),
    }
}

/// A node page's fragment once the node has been removed.
fn gone() -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"empty\">This node has been removed from the hub.</p>");
    h
}

/// A node's page below its name: everything the hub knows of it.
fn node_detail(d: &NodeDetail, now: u64) -> Html {
    let v = &d.view;
    let mut h = Html::new();
    h.raw("<p class=\"sub\"><code>")
        .text(&v.id)
        .raw("</code> · ")
        .raw(if v.connected {
            "connected"
        } else {
            "unreachable"
        })
        .raw(" · last seen ")
        .text(
            v.last_seen
                .map_or_else(|| "never".to_string(), |t| age(now, t)),
        )
        .raw("</p>");

    steering(&mut h, d, now);

    let heartbeat = d.row.heartbeat.as_ref();
    section(&mut h, "Load");
    match heartbeat {
        None => kv(&mut h, "heartbeat", "none yet"),
        Some(hb) => {
            if let Some(at) = d.row.heartbeat_at {
                kv(&mut h, "heartbeat", &age(now, at));
            }
            match &hb.admission {
                Some(a) => {
                    kv(
                        &mut h,
                        "admitted memory",
                        &format!(
                            "{} of {}",
                            mib(a.committed_mib),
                            a.budget_mib.map_or_else(|| "no budget".to_string(), mib)
                        ),
                    );
                    kv(
                        &mut h,
                        "jobs",
                        &format!("{} admitted, {} waiting", a.running, a.waiting),
                    );
                }
                None => kv(&mut h, "admission", "unreadable"),
            }
            kv(
                &mut h,
                "memory available",
                &hb.mem_available_mib
                    .map_or_else(dash, |m| rough_bytes(m.saturating_mul(1 << 20))),
            );
            kv(
                &mut h,
                "concurrency asked of the runner",
                &count(hb.desired_concurrency),
            );
        }
    }
    end_section(&mut h);

    workloads(&mut h, d.workloads.as_ref());

    let inventory = d.row.inventory.as_ref();
    section(&mut h, "Hardware");
    match inventory {
        None => kv(&mut h, "inventory", "none yet"),
        Some(inv) => {
            let hw = &inv.hardware;
            kv(&mut h, "CPUs", &hw.cpus.to_string());
            kv_node(&mut h, "CPU model", hw.cpu_model.as_deref().unwrap_or("-"));
            kv(&mut h, "memory", &hw.mem_total_mib.map_or_else(dash, mib));
            for m in &hw.memory_nodes {
                kv(
                    &mut h,
                    &format!("memory node {}", m.id),
                    &format!("{} CPUs, {}", m.cpus, mib(m.mem_total_mib)),
                );
            }
            for c in &hw.checks {
                h.raw("<tr><th>check ").node(&c.name).raw("</th><td>");
                if c.ok {
                    h.raw("ok");
                } else {
                    h.raw("failed: ").node(&c.detail);
                }
                h.raw("</td></tr>");
            }
        }
    }
    end_section(&mut h);

    if let Some(inv) = inventory {
        h.raw("<section><h2>Storage</h2>");
        if inv.storage.is_empty() {
            h.raw("<p class=\"empty\">none reported</p>");
        } else {
            h.raw("<table class=\"grid\"><thead><tr><th>role</th><th>path</th><th>device</th>")
                .raw("<th>size</th><th>kind</th><th>speed</th><th>free</th>")
                .raw("<th>free inodes</th></tr></thead><tbody>");
            for fs in &inv.storage {
                let usage = heartbeat.and_then(|hb| hb.storage.iter().find(|u| u.role == fs.role));
                h.raw("<tr><td>")
                    .raw(match fs.role {
                        StorageRole::Jobs => "jobs",
                        StorageRole::Checkouts => "checkouts",
                    })
                    .raw("</td><td>")
                    .node(&fs.path)
                    .raw("</td><td>")
                    .node(&fs.device)
                    .raw("</td><td>")
                    .text(bytes(fs.size_bytes))
                    .raw("</td><td>")
                    .raw(if fs.tmpfs { "tmpfs" } else { "disk" })
                    .raw("</td><td>")
                    .raw(match fs.speed {
                        Some(SpeedClass::Fast) => "fast",
                        Some(SpeedClass::Slow) => "slow",
                        None => "-",
                    })
                    .raw("</td><td>")
                    .text(usage.map_or_else(dash, |u| bytes(u.free_bytes)))
                    .raw("</td><td>")
                    .text(usage.map_or_else(dash, |u| {
                        if u.inodes == 0 {
                            rough_count(u.free_inodes)
                        } else {
                            format!(
                                "{} of {}",
                                rough_count(u.free_inodes),
                                rough_count(u.inodes)
                            )
                        }
                    }))
                    .raw("</td></tr>");
            }
            h.raw("</tbody></table>");
        }
        h.raw("</section>");

        section(&mut h, "Versions");
        kv_node(&mut h, "vk", &inv.versions.vk);
        kv_node(
            &mut h,
            "guest kernel",
            inv.versions.guest_kernel.as_deref().unwrap_or("-"),
        );
        kv_node(&mut h, "configuration hash", &inv.versions.config_hash);
        end_section(&mut h);

        section(&mut h, "Runner");
        match &inv.runner {
            None => kv(&mut h, "configuration", "unreadable"),
            Some(r) => {
                kv_node(&mut h, "configuration", &r.config);
                kv(&mut h, "concurrent", &count(r.concurrent));
                h.raw("<tr><th>runners</th><td>");
                for (i, name) in r.runners.iter().enumerate() {
                    if i > 0 {
                        h.raw(", ");
                    }
                    h.node(name);
                }
                h.raw("</td></tr>");
            }
        }
        end_section(&mut h);
    }

    h
}

/// Show desired and reported state and recent commands, or a monitoring-only notice.
fn steering(h: &mut Html, d: &NodeDetail, now: u64) {
    let v = &d.view;
    if let Some(version) = v.protocol.filter(|_| v.monitoring_only()) {
        section(h, "Steering");
        kv(
            h,
            "steering",
            &format!(
                "none: the node speaks fleet protocol version {version}, so the hub monitors it \
                 and cannot steer it; update its vk"
            ),
        );
        end_section(h);
        return;
    }

    section(h, "Asked by the hub");
    match &v.desired {
        None => kv(
            h,
            "desired state",
            "nothing asked: no ceiling, acquisition running",
        ),
        Some(desired) => {
            kv(h, "generation", &desired.generation.to_string());
            kv(h, "ceiling", &count(desired.ceiling));
            kv(
                h,
                "acquisition",
                crate::acquisition_name(desired.acquisition),
            );
        }
    }
    kv(h, "sync", &crate::node_cells(v, now)[NODE_SYNC]);
    end_section(h);

    section(h, "Reported by the node");
    match &v.report {
        None => kv(h, "report", "none yet"),
        Some(r) => {
            let or_dash = |s: Option<&str>| s.unwrap_or("-").to_string();
            kv(
                h,
                "applied generation",
                &r.applied_generation.map_or_else(dash, |g| g.to_string()),
            );
            kv(h, "state", &or_dash(r.state.map(crate::store::state_name)));
            kv(
                h,
                "acquisition",
                &or_dash(r.acquisition.map(crate::acquisition_name)),
            );
            kv(
                h,
                "runner",
                &or_dash(r.runner.map(|m| match m {
                    RunnerMode::Managed => "managed",
                    RunnerMode::External => "external",
                })),
            );
            if let Some(state) = r.runner_state {
                kv(
                    h,
                    "runner process",
                    match state {
                        RunnerState::Running => "running",
                        RunnerState::Quitting => "quitting: finishing its jobs",
                        RunnerState::Stopped => "stopped",
                    },
                );
            }
            if let Some(c) = r.concurrency {
                kv(
                    h,
                    "concurrency",
                    &format!(
                        "{}: the least of the estimate {}, the hub's ceiling {} and the local \
                         ceiling {}",
                        count(c.effective),
                        count(c.estimate),
                        count(c.hub_ceiling),
                        count(c.local_ceiling)
                    ),
                );
            }
            if let Some(p) = r.drain {
                kv(
                    h,
                    "drain",
                    &format!(
                        "runner {}, admission ledger {}, {} job(s) running",
                        if p.runner_stopped {
                            "stopped"
                        } else {
                            "still running"
                        },
                        if p.ledger_empty { "empty" } else { "in use" },
                        p.active_jobs
                    ),
                );
            }
            for note in &r.unsupported {
                kv_node(h, "cannot comply", note);
            }
            if let Some(e) = &r.concurrency_error {
                kv_node(h, "cannot set its concurrency", e);
            }
        }
    }
    end_section(h);

    commands(h, d, now);
}

/// The node's latest commands and what it made of them.
fn commands(h: &mut Html, d: &NodeDetail, now: u64) {
    h.raw("<section><h2>Commands</h2>");
    if d.commands.is_empty() {
        h.raw("<p class=\"empty\">none</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>issued</th><th>command</th>")
            .raw("<th>outcome</th><th>expires</th></tr></thead><tbody>");
        for c in &d.commands {
            h.raw("<tr><td>")
                .text(started(c.issued_at))
                .raw("</td><td>")
                .text(crate::store::operation_name(&c.command.op))
                .raw(" <code>")
                .text(&c.command.id)
                .raw("</code></td><td>");
            match &c.outcome {
                None if c.command.expires_at <= now => h.raw("expired, never taken"),
                None => h.raw("not taken yet"),
                Some(Outcome::Accepted) => h.raw("under way"),
                Some(Outcome::Done) => h.raw("done"),
                Some(Outcome::Failed { message }) => h.raw("failed: ").node(message),
                Some(Outcome::Refused { reason }) => h.raw("refused: ").node(reason),
                Some(Outcome::Expired) => h.raw("expired"),
            };
            h.raw("</td><td>")
                .text(started(c.command.expires_at))
                .raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    // The node's ID: the router took it as hex.
    h.raw("<p><a href=\"/audit?node=")
        .text(&d.view.id)
        .raw("\">the node's audit log</a></p></section>");
}

/// The VMs the node reports running, with what each holds from the last heartbeat. Every
/// cell is the node's but the kind and the figures the hub formats.
fn workloads(h: &mut Html, workloads: Option<&crate::store::Workloads>) {
    h.raw("<section><h2>Workloads</h2>");
    let Some(workloads) = workloads else {
        h.raw("<p class=\"empty\">not reported yet</p></section>");
        return;
    };
    let list = &workloads.listed;
    if list.is_empty() && workloads.omitted == 0 {
        h.raw("<p class=\"empty\">none running</p></section>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr>");
    for column in crate::workloads::COLUMNS {
        h.raw("<th>").text(column).raw("</th>");
    }
    h.raw("</tr></thead><tbody>");
    for w in list {
        let mem = workloads.mem_bytes.get(&w.id).copied();
        let mut cells = crate::workloads::cells(w, mem);
        // Use the page's units. Round changing memory usage to two significant figures
        // so small fluctuations do not update the page.
        cells[VM_RESERVED] = w.mem_reserved_mib.map_or_else(dash, mib);
        cells[VM_IN_USE] = mem.map_or_else(dash, rough_bytes);
        cells[VM_STARTED] = w.started_at.map_or_else(dash, started);
        h.raw("<tr>");
        for (i, cell) in cells.iter().enumerate() {
            h.raw("<td>");
            match i {
                // Of the hub's making: the kind's name and the figures.
                VM_KIND | VM_PID..=VM_STARTED => h.text(cell),
                VM_ID => h.raw("<code>").node(cell).raw("</code>"),
                _ => h.node(cell),
            };
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
    if workloads.omitted > 0 {
        h.raw("<p class=\"empty\">and ")
            .text(workloads.omitted)
            .raw(" more running, not listed</p>");
    }
    h.raw("</section>");
}
