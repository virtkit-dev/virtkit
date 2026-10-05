//! The fleet's site, for `vk-hub serve`: the nodes table, a page per node with its
//! inventory, load and workloads, and the audit log by node. Read-only: nothing here changes
//! a node.

use std::sync::Arc;

use anyhow::Result;
use hyper::{Response, StatusCode};
use vk_hub_proto::{SpeedClass, StorageRole};

use super::html::Html;
use super::pages::{
    self, bytes, count, dash, end_section, kv, kv_node, mib, rough_bytes, rough_count, section,
    started,
};
use super::sse::{self, Source};
use super::{Auth, Body, Ui, blocking, decode_form, field, message, page};
use crate::ops::NodeView;
use crate::server::{HEARTBEAT, Hub};
use crate::store::NodeRow;

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
    Ok(Some(NodeDetail {
        view: crate::ops::node_view(hub, id.to_string(), &row),
        workloads,
        row,
    }))
}

/// What a node's page shows.
struct NodeDetail {
    view: NodeView,
    row: NodeRow,
    /// `None` until the node has listed any.
    workloads: Option<crate::store::Workloads>,
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
/// The node's ID goes into `sse-connect`: it is one the hub issued, and the router takes only
/// hex for one.
fn node(auth: &Auth, detail: &NodeDetail, now: u64) -> Html {
    let id = &detail.view.id;
    let mut main = Html::new();
    main.raw("<h1>").node(&detail.view.hostname).raw("</h1>");
    main.raw("<div id=\"detail\" hx-ext=\"sse\" sse-connect=\"/events/node/")
        .text(id)
        .raw("\" sse-swap=\"node\" sse-close=\"close\">")
        .html(&node_detail(detail, now))
        .raw("</div>");
    layout(&detail.view.hostname, auth, &main)
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
