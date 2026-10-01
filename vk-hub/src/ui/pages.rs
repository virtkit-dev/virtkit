//! The pages, as [`Html`]: the nodes table, a node's detail, the audit log. Every value in
//! them goes through [`Html::text`] or, for what a node sent, [`Html::node`].

use std::collections::HashMap;

use vk_fleet_proto::{Outcome, RunnerMode, RunnerState, SpeedClass, StorageRole};

use super::Auth;
use super::assets;
use super::html::Html;
use crate::ops::NodeView;
use crate::server::HEARTBEAT;
use crate::store::{AuditRow, CommandRow, NodeRow, Role};

/// Audit lines per page of `/audit`.
pub const AUDIT_PAGE: usize = 100;
/// A node page's latest commands and audit lines.
pub const NODE_COMMANDS: usize = 20;
pub const NODE_AUDIT: usize = 30;

/// What a node's page shows.
pub struct NodeDetail {
    pub view: NodeView,
    pub row: NodeRow,
    /// Newest first.
    pub commands: Vec<CommandRow>,
    /// Newest first, with their sequence numbers.
    pub audit: Vec<(u64, AuditRow)>,
}

/// One page of `/audit`.
pub struct AuditPage {
    /// The node it is filtered to, if any.
    pub node: Option<String>,
    /// Newest first, with their sequence numbers.
    pub rows: Vec<(u64, AuditRow)>,
}

/// The page around `main`: head, stylesheet, navigation, who is signed in.
pub fn layout(title: &str, auth: &Auth, main: &Html) -> Html {
    frame(title, auth, FLEET_NAV, main)
}

/// The fleet's navigation.
pub const FLEET_NAV: &str = "<a href=\"/\">nodes</a> <a href=\"/audit\">audit</a>";

/// [`layout`], with the site's own navigation, `nav`.
pub fn frame(title: &str, auth: &Auth, nav: &'static str, main: &Html) -> Html {
    let mut h = Html::new();
    head(&mut h, title);
    h.raw("<body><header><nav>")
        .raw(nav)
        .raw("</nav><form class=\"who\" method=\"post\" action=\"/logout\"><span>")
        .text(auth.session.principal())
        .raw(", until ")
        .text(crate::utc(auth.session.expires_at))
        .raw("</span> ");
    csrf_field(&mut h, auth);
    h.raw("<button>sign out</button></form></header><main>")
        .html(main)
        .raw("</main></body></html>");
    h
}

/// htmx's configuration: nothing evaluated, no script run from a swapped fragment, no
/// inline style of its own (the policy would refuse it), requests to this origin only — and
/// a refusal (4xx) swapped rather than dropped, so the line saying why shows, without
/// logging it as an error.
const HTMX_CONFIG: &str = r#"{"allowEval":false,"allowScriptTags":false,"includeIndicatorStyles":false,"selfRequestsOnly":true,"responseHandling":[{"code":"204","swap":false},{"code":"[23]..","swap":true},{"code":"4..","swap":true,"error":false},{"code":"...","swap":false,"error":true}]}"#;

fn head(h: &mut Html, title: &str) {
    h.raw("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
        .raw("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
        .raw("<meta name=\"htmx-config\" content='")
        .raw(HTMX_CONFIG)
        .raw("'><title>")
        .node(title)
        .raw(" · vk-hub</title><link rel=\"stylesheet\" href=\"")
        .text(assets::url(assets::CSS))
        .raw("\"><script src=\"")
        .text(assets::url(assets::HTMX))
        .raw("\"></script><script src=\"")
        .text(assets::url(assets::SSE))
        .raw("\"></script></head>");
}

/// The hidden field carrying the session's CSRF token.
pub fn csrf_field(h: &mut Html, auth: &Auth) {
    h.raw("<input type=\"hidden\" name=\"_csrf\" value=\"")
        .text(&auth.csrf)
        .raw("\">");
}

/// A page with one sentence and no session: an error, or signed out.
pub fn message(text: &str) -> Html {
    let mut h = Html::new();
    head(&mut h, "vk-hub");
    h.raw("<body><main><p class=\"message\">")
        .text(text)
        .raw("</p></main></body></html>");
    h
}

/// `GET /login`: the sign-in link's page, a button posting its token back.
pub fn sign_in(token: &str) -> Html {
    let mut h = Html::new();
    head(&mut h, "sign in");
    h.raw("<body><main><form class=\"message\" method=\"post\" action=\"/login\">")
        .raw("<input type=\"hidden\" name=\"t\" value=\"")
        .text(token)
        .raw("\"><p>This link signs this browser in to the hub's web UI, once.</p>")
        .raw("<button>Sign in</button></form></main></body></html>");
    h
}

/// What signing in answers: on to `/` by the page's own navigation, with a link for a
/// browser that does not follow a refresh.
pub fn signed_in() -> Html {
    let mut h = Html::new();
    h.raw("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
        .raw("<meta http-equiv=\"refresh\" content=\"0; url=/\"><title>vk-hub</title></head>")
        .raw("<body><p><a href=\"/\">Signed in; continue</a></p></body></html>");
    h
}

/// `/`: the nodes table.
pub fn nodes(auth: &Auth, nodes: &[NodeView], now: u64) -> Html {
    let mut main = Html::new();
    main.raw("<h1>Nodes</h1>")
        .raw("<div id=\"nodes\" hx-ext=\"sse\" sse-connect=\"/events/nodes\" sse-swap=\"nodes\" sse-close=\"close\">")
        .html(&nodes_table(nodes, now))
        .raw("</div>");
    layout("nodes", auth, &main)
}

/// The nodes table with the columns of `vk-hub nodes`, and each node's notes under it.
pub fn nodes_table(nodes: &[NodeView], now: u64) -> Html {
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
        cells[8] = n
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
                0 | 1 => {
                    h.raw("<a href=\"/node/").text(&n.id).raw("\">");
                    if i == 0 {
                        h.text(n.id.get(..8).unwrap_or(&n.id));
                    } else {
                        h.node(cell);
                    }
                    h.raw("</a>");
                }
                // What the node sent: its version.
                9 => {
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
    // What a node says it cannot do, as `vk-hub nodes` puts it under its table.
    let mut notes = Html::new();
    for n in nodes {
        let Some(report) = &n.report else {
            continue;
        };
        for note in &report.unsupported {
            notes
                .raw("<li>")
                .node(&n.hostname)
                .raw(": cannot comply: ")
                .node(note)
                .raw("</li>");
        }
        if let Some(error) = &report.concurrency_error {
            notes
                .raw("<li>")
                .node(&n.hostname)
                .raw(": cannot set its concurrency: ")
                .node(error)
                .raw("</li>");
        }
    }
    if !notes.is_empty() {
        h.raw("<ul class=\"notes\">").html(&notes).raw("</ul>");
    }
    h
}

/// `/node/<id>`.
///
/// The node's ID goes into `sse-connect` and `hx-post`: it is one the hub issued, and the
/// router takes only hex for one.
pub fn node(auth: &Auth, detail: &NodeDetail, now: u64) -> Html {
    let id = &detail.view.id;
    let mut main = Html::new();
    main.raw("<h1>").node(&detail.view.hostname).raw("</h1>");
    if auth.session.role >= Role::Operator {
        actions(&mut main, auth, id);
    }
    main.raw("<div id=\"detail\" hx-ext=\"sse\" sse-connect=\"/events/node/")
        .text(id)
        .raw("\" sse-swap=\"node\" sse-close=\"close\">")
        .html(&node_detail(detail, now))
        .raw("</div>");
    layout(&detail.view.hostname, auth, &main)
}

/// The operator's forms, outside the live fragment so an update never clears one being
/// filled in. Each posts to the node's action with htmx, and works as a plain form too.
fn actions(h: &mut Html, auth: &Auth, id: &str) {
    h.raw("<section><h2>Steer</h2><div class=\"actions\">");
    let form = |h: &mut Html, op: &'static str| {
        h.raw("<form method=\"post\" action=\"/node/")
            .text(id)
            .raw("/action\" hx-post=\"/node/")
            .text(id)
            .raw("/action\" hx-target=\"#detail\">");
        csrf_field(h, auth);
        h.raw("<input type=\"hidden\" name=\"op\" value=\"")
            .raw(op)
            .raw("\">");
    };
    form(h, "ceiling");
    h.raw("<input type=\"number\" name=\"ceiling\" min=\"1\" required ")
        .raw("aria-label=\"ceiling\"><button>set ceiling</button></form>");
    for (op, label) in [
        ("lift-ceiling", "lift ceiling"),
        ("stop", "stop acquisition"),
        ("resume", "resume acquisition"),
        ("drain", "drain"),
        ("undrain", "undrain"),
        ("quarantine", "quarantine"),
        ("release", "release"),
    ] {
        form(h, op);
        h.raw("<button>").raw(label).raw("</button></form>");
    }
    h.raw("</div><div id=\"flash\"></div></section>");
}

/// The line saying what an action came to, swapped into its place out of band. The hub's
/// own words, whole.
pub fn flash(text: &str, error: bool) -> Html {
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\"")
        .raw(if error { " class=\"error\"" } else { "" })
        .raw(">")
        .text(text)
        .raw("</div>");
    h
}

/// A live region's last fragment, once its session has ended.
pub fn signed_out_fragment() -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"message\">Signed out: this page no longer updates. ")
        .raw("A new sign-in link signs you in again.</p>");
    h
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
pub fn gone() -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"empty\">This node has been removed from the hub.</p>");
    h
}

/// A node's page below its name: everything the hub knows of it.
pub fn node_detail(d: &NodeDetail, now: u64) -> Html {
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

    let report = d.row.report.as_ref();
    let desired = d.row.desired.as_ref();
    let cells = crate::node_cells(v, now);
    section(&mut h, "Steering");
    kv(&mut h, "state", &cells[3]);
    kv(&mut h, "acquisition", &cells[4]);
    kv(&mut h, "ceiling", &cells[5]);
    kv(
        &mut h,
        "desired generation",
        &desired.map_or_else(dash, |d| d.generation.to_string()),
    );
    kv(
        &mut h,
        "applied generation",
        &report
            .and_then(|r| r.applied_generation)
            .map_or_else(dash, |g| g.to_string()),
    );
    kv(&mut h, "sync", &cells[7]);
    end_section(&mut h);

    section(&mut h, "Report");
    match report {
        None => kv(&mut h, "report", "none yet"),
        Some(r) => {
            kv(
                &mut h,
                "runner",
                match r.runner {
                    RunnerMode::Managed => "managed",
                    RunnerMode::External => "external",
                },
            );
            kv(
                &mut h,
                "runner process",
                r.runner_state.map_or("-", |s| match s {
                    RunnerState::Running => "running",
                    RunnerState::Quitting => "quitting",
                    RunnerState::Stopped => "stopped",
                }),
            );
            kv(
                &mut h,
                "node's acquisition",
                crate::acquisition_name(r.acquisition),
            );
            if let Some(c) = r.concurrency {
                kv(
                    &mut h,
                    "concurrency",
                    &format!(
                        "effective {} = min(estimate {}, hub ceiling {}, local ceiling {})",
                        count(c.effective),
                        count(c.estimate),
                        count(c.hub_ceiling),
                        count(c.local_ceiling)
                    ),
                );
            }
            if let Some(e) = &r.concurrency_error {
                kv_node(&mut h, "cannot set its concurrency", e);
            }
            for note in &r.unsupported {
                kv_node(&mut h, "cannot comply", note);
            }
            if let Some(p) = r.drain {
                kv(
                    &mut h,
                    "drain",
                    &format!(
                        "runner {}, admission ledger {}, {} job(s) still running",
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
        }
    }
    end_section(&mut h);

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
                &hb.mem_available_mib.map_or_else(dash, mib),
            );
            kv(
                &mut h,
                "concurrency asked of the runner",
                &count(hb.desired_concurrency),
            );
        }
    }
    end_section(&mut h);

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
                            u.free_inodes.to_string()
                        } else {
                            format!("{} of {}", u.free_inodes, u.inodes)
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

    h.raw("<section><h2>Commands</h2>");
    if d.commands.is_empty() {
        h.raw("<p class=\"empty\">none</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>issued</th><th>command</th>")
            .raw("<th>outcome</th><th>expires</th></tr></thead><tbody>");
        for c in &d.commands {
            h.raw("<tr><td>")
                .text(crate::utc(c.issued_at))
                .raw("</td><td>")
                .text(crate::store::operation_name(&c.command.op))
                .raw(" <code>")
                .text(&c.command.id)
                .raw("</code></td><td>");
            outcome(&mut h, c.outcome.as_ref());
            h.raw("</td><td>")
                .text(crate::utc(c.command.expires_at))
                .raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section><section><h2>Recent audit</h2>");
    audit_table(&mut h, &d.audit, &HashMap::new(), false);
    h.raw("<p><a href=\"/audit?node=")
        .text(&v.id)
        .raw("\">the node's whole audit log</a></p></section>");
    h
}

/// `/audit`: the log, newest first, a page at a time, maybe of one node.
///
/// `names` are the nodes, by ID, that the filter offers; `nav` the site's navigation.
pub fn audit(auth: &Auth, page: &AuditPage, names: &[(String, String)], nav: &'static str) -> Html {
    let names: HashMap<&str, &str> = names
        .iter()
        .map(|(id, name)| (id.as_str(), name.as_str()))
        .collect();
    let mut main = Html::new();
    main.raw("<h1>Audit</h1>");
    // Nodes to filter by: none in local mode, where nothing is a node's.
    if !names.is_empty() {
        main.raw("<form class=\"filter\" method=\"get\" action=\"/audit\">")
            .raw("<select name=\"node\"><option value=\"\">every node</option>");
        let mut sorted: Vec<(&str, &str)> = names.iter().map(|(id, n)| (*id, *n)).collect();
        sorted.sort_by_key(|(id, name)| (*name, *id));
        for (id, name) in sorted {
            main.raw("<option value=\"").text(id).raw("\"");
            if page.node.as_deref() == Some(id) {
                main.raw(" selected");
            }
            main.raw(">")
                .node(name)
                .raw(" (")
                .text(id.get(..8).unwrap_or(id))
                .raw(")</option>");
        }
        main.raw("</select> <button>show</button></form>");
    }
    audit_table(&mut main, &page.rows, &names, !names.is_empty());
    if page.rows.len() == AUDIT_PAGE
        && let Some((oldest, _)) = page.rows.last()
    {
        main.raw("<p><a href=\"/audit?");
        if let Some(node) = &page.node {
            main.raw("node=").text(node).raw("&amp;");
        }
        main.raw("before=").text(oldest).raw("\">older</a></p>");
    }
    frame("audit", auth, nav, &main)
}

fn audit_table(
    h: &mut Html,
    rows: &[(u64, AuditRow)],
    names: &HashMap<&str, &str>,
    with_node: bool,
) {
    if rows.is_empty() {
        h.raw("<p class=\"empty\">nothing yet</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>when</th>");
    if with_node {
        h.raw("<th>node</th>");
    }
    h.raw("<th>who</th><th>what</th></tr></thead><tbody>");
    for (_, row) in rows {
        h.raw("<tr><td>").text(crate::utc(row.at)).raw("</td>");
        if with_node {
            h.raw("<td>");
            match row.node.as_deref() {
                Some(id) if vk_fleet_proto::valid_id(id) => {
                    h.raw("<a href=\"/node/").text(id).raw("\">");
                    match names.get(id) {
                        Some(name) => h.node(name),
                        None => h.text(id.get(..8).unwrap_or(id)),
                    };
                    h.raw("</a>");
                }
                Some(id) => {
                    h.node(id);
                }
                None => {
                    h.raw("-");
                }
            }
            h.raw("</td>");
        }
        // The event holds what nodes or the host's `vk` said, made display-safe as the store
        // wrote it.
        h.raw("<td>")
            .text(&row.actor)
            .raw("</td><td>")
            .node(&row.event)
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

pub fn section(h: &mut Html, title: &'static str) {
    h.raw("<section><h2>")
        .raw(title)
        .raw("</h2><table class=\"kv\"><tbody>");
}

pub fn end_section(h: &mut Html) {
    h.raw("</tbody></table></section>");
}

/// A row of a key/value table, both of the hub's making.
pub fn kv(h: &mut Html, key: &str, value: &str) {
    h.raw("<tr><th>")
        .text(key)
        .raw("</th><td>")
        .text(value)
        .raw("</td></tr>");
}

/// A row whose value is what a node sent.
pub fn kv_node(h: &mut Html, key: &'static str, value: &str) {
    h.raw("<tr><th>")
        .text(key)
        .raw("</th><td>")
        .node(value)
        .raw("</td></tr>");
}

pub fn dash() -> String {
    "-".to_string()
}

fn count(n: Option<u32>) -> String {
    n.map_or_else(dash, |n| n.to_string())
}

pub fn mib(n: u64) -> String {
    bytes(n.saturating_mul(1 << 20))
}

/// `n` bytes in binary units, one decimal past the first.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).unwrap_or(&"B");
    if unit == 0 {
        format!("{n} {name}")
    } else {
        format!("{value:.1} {name}")
    }
}

/// When something started, to the minute: fixed, where an uptime would move the page on for
/// every workload as each of them turned another minute.
pub fn started(secs: u64) -> String {
    let mut at = crate::utc(secs);
    // `YYYY-MM-DDTHH:MM:SSZ` without the seconds.
    at.replace_range(16..19, "");
    at
}

/// `n` bytes in binary units to two significant figures: for a reading that moves by the
/// second, which would otherwise change its page on every look.
pub fn rough_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).unwrap_or(&"B");
    format!("{} {name}", two_figures(value))
}

/// `value`, below a thousand, to two significant figures.
fn two_figures(value: f64) -> String {
    if value >= 100.0 {
        format!("{:.0}", (value / 10.0).round() * 10.0)
    } else if value >= 10.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

/// What a command came to; a node's own words are its.
fn outcome(h: &mut Html, o: Option<&Outcome>) {
    match o {
        None => h.raw("not yet taken"),
        Some(Outcome::Accepted) => h.raw("under way"),
        Some(Outcome::Done) => h.raw("done"),
        Some(Outcome::Failed { message }) => h.raw("failed: ").node(message),
        Some(Outcome::Refused { reason }) => h.raw("refused: ").node(reason),
        Some(Outcome::Expired) => h.raw("expired"),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What moves by the second is shown in steps coarse enough that an idle page stays put.
    #[test]
    fn readings_are_shown_to_two_figures_and_start_times_to_the_minute() {
        assert_eq!(rough_bytes(197 << 20), "200 MiB");
        assert_eq!(rough_bytes(3 << 30), "3.0 GiB");
        assert_eq!(started(1_790_755_279), "2026-09-30T08:01Z");
    }
}
