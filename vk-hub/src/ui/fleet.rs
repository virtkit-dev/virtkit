//! The fleet site for `vk-hub serve`: the nodes table, per-node inventory, load, workloads,
//! steering, commands, releases and rollouts, and the audit log. Operators steer nodes and
//! pause, resume or abort rollouts through the shared admin-socket operations ([`crate::ops`])
//! as their session's principal; a node's page offers, in plain words, only those that apply
//! to where the node stands ([`Panel`]). A reset, which deletes what the node's past jobs
//! left, is confirmed first ([`actions::ask_first`]). Monitoring-only nodes have no steering
//! controls.
//! Operators add releases and start rollouts from `/operations` ([`super::operations`]); the
//! jobs placed through the client API are listed, read only, on `/jobs` ([`super::jobs`]).
//! Operators issue enrollment tokens from the nodes page ([`create_token`]), and grant OIDC
//! sign-in roles from `/users` ([`super::users`]), which only their navigation links to.

use std::sync::Arc;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::{
    Acquisition, Operation, Outcome, RunnerMode, RunnerState, SpeedClass, StorageRole, WorkloadKind,
};

use super::html::Html;
use super::pages::{
    self, bytes, column_is, count, dash, end_section, header_cells, kv, kv_html, kv_node, mib,
    open_cell, rough_bytes, rough_count, section, started,
};
use super::sse::{self, Source};
use super::{Auth, Body, Ui, actions, blocking, decode_form, field, message, operations, page};
use crate::ops::{self, NodeView};
use crate::rollout::{NodeStatus, Rollout, RolloutAction, RolloutState};
use crate::server::{HEARTBEAT, Hub};
use crate::store::{
    CommandRow, MonitoringOnly, NodeRow, NotEnrolled, Release, Role, RolloutConflict,
};

/// A node page's latest commands.
const NODE_COMMANDS: usize = 20;

/// Where the nodes page's form issues an enrollment token.
pub(super) const TOKEN_PATH: &str = "/tokens";

/// Token lifetimes offered by the form, in seconds. The first is the default, matching
/// `vk-hub token create`; the CLI accepts any lifetime up to the store's limit.
const TOKEN_TTLS: [(u64, &str); 4] = [
    (3_600, "1 hour"),
    (600, "10 minutes"),
    (86_400, "1 day"),
    (7 * 86_400, "7 days"),
];

/// The rollouts `/operations` shows, newest first.
const OPERATIONS_ROLLOUTS: usize = 10;

/// What the fleet's pages keep: the nodes table, and `/operations`' fragment once for every
/// viewer's page and once for every operator's, each rendered once for every page showing it
/// ([`sse::feed`]). `/operations` shows only releases and rollouts, so it follows
/// [`Hub::touch`] alone, not every node's heartbeat.
pub(super) struct FleetSite {
    /// Pending reset and rollout confirmations.
    pub(super) questions: actions::Questions,
    /// Whether a release is being uploaded.
    pub(super) uploading: operations::Uploading,
    nodes_feed: tokio::sync::watch::Sender<Option<bytes::Bytes>>,
    operations_feed: tokio::sync::watch::Sender<Option<bytes::Bytes>>,
    steered_operations_feed: tokio::sync::watch::Sender<Option<bytes::Bytes>>,
}

impl FleetSite {
    pub(super) fn new(hub: &Arc<Hub>) -> Self {
        FleetSite {
            questions: actions::Questions::new(),
            uploading: operations::Uploading::new(),
            nodes_feed: sse::feed(hub.subscribe(), "nodes", render_nodes(hub.clone())),
            operations_feed: sse::feed(
                hub.subscribe_touched(),
                "operations",
                render_operations(hub.clone(), false),
            ),
            steered_operations_feed: sse::feed(
                hub.subscribe_touched(),
                "operations",
                render_operations(hub.clone(), true),
            ),
        }
    }
}

/// The event `/events/<event>` swaps its fragment in on, if it is one of the fleet's.
pub(super) fn event_name(event: &str) -> Option<&'static str> {
    match event {
        "nodes" => Some("nodes"),
        "operations" => Some("operations"),
        _ => event
            .strip_prefix("node/")
            .filter(|id| vk_hub_proto::valid_id(id))
            .map(|_| "node"),
    }
}

/// A fleet `/events/<event>` stream for `auth`'s page. Operators see rollout buttons on
/// `/operations` and node steering actions rendered per stream with the session's CSRF token.
pub(super) fn source(event: &str, hub: &Arc<Hub>, site: &FleetSite, auth: &Auth) -> Option<Source> {
    let steer = auth.session.role >= Role::Operator;
    match event {
        "nodes" => {
            return Some(Source::Shared {
                name: "nodes",
                feed: site.nodes_feed.subscribe(),
                render: render_nodes(hub.clone()),
            });
        }
        "operations" => {
            let feed = if steer {
                &site.steered_operations_feed
            } else {
                &site.operations_feed
            };
            return Some(Source::Shared {
                name: "operations",
                feed: feed.subscribe(),
                render: render_operations(hub.clone(), steer),
            });
        }
        _ => {}
    }
    let id = event
        .strip_prefix("node/")
        .filter(|id| vk_hub_proto::valid_id(id))?
        .to_string();
    let hub = hub.clone();
    let csrf = steer_token(auth).map(str::to_string);
    Some(Source::Own {
        name: "node",
        changes: hub.subscribe_node(&id),
        render: Arc::new(move || render_node(&hub, &id, csrf.as_deref())),
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
    if path == "/operations" {
        let steer = auth.session.role >= Role::Operator;
        let (ops, nodes) = blocking(move || {
            // The forms' nodes, for an operator's page alone.
            let nodes = if steer {
                crate::ops::node_views(&hub)?
            } else {
                Vec::new()
            };
            Ok((read_operations(&hub)?, nodes))
        })
        .await?;
        return Ok(Some(page(operations(auth, &ops, &nodes, now))));
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
        return Ok(Some(page(pages::audit(
            auth,
            &audit,
            Some(&names),
            nav(auth),
        ))));
    }
    if path == super::users::PATH {
        return super::users::get(auth, ui).await.map(Some);
    }
    if path == super::jobs::PATH {
        return super::jobs::get(query, auth, ui).await.map(Some);
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

/// `/operations`' fragment, as one rendering for every page showing it: with the rollouts'
/// buttons for an operator's, without for a viewer's.
fn render_operations(hub: Arc<Hub>, steer: bool) -> sse::Render {
    Arc::new(move || {
        let ops = read_operations(&hub)?;
        Ok(operations_fragment(&ops, steer, crate::now_secs()).into_string())
    })
}

/// What `/operations` shows.
fn read_operations(hub: &Hub) -> Result<Operations> {
    let mut rollouts = ops::rollouts(hub)?;
    rollouts.truncate(OPERATIONS_ROLLOUTS);
    Ok(Operations {
        releases: hub.db.releases()?,
        rollouts,
        source: hub.fetches.source().map(|s| s.url().to_string()),
        fetch: hub.fetches.status(),
        latest: hub.fetches.latest(),
    })
}

/// What `/operations` shows.
struct Operations {
    releases: Vec<Release>,
    /// The latest, newest first.
    rollouts: Vec<Rollout>,
    /// Where releases are fetched from; `None` with fetching off.
    source: Option<String>,
    /// The latest fetch since the hub started.
    fetch: Option<crate::fetch::FetchStatus>,
    /// The latest release the repository named when last asked, and when.
    latest: Option<(String, u64)>,
}

/// Node `id`'s page fragment, with its steering actions given `csrf`, or the line saying it
/// has gone.
fn render_node(hub: &Hub, id: &str, csrf: Option<&str>) -> Result<String> {
    Ok(match read_node(hub, id)? {
        Some(detail) => node_detail(&detail, crate::now_secs(), csrf).into_string(),
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
        "reset" => Steer::Command(Operation::Reset { images: false }),
        _ => return Err("No such action."),
    })
}

/// `POST /node/<id>/action`: run the shared admin-socket operation as the operator's session
/// principal. For htmx, return a status line while the node's fragment updates live.
/// For plain forms, redirect to the node's page or show the refusal.
pub(super) async fn node_action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
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
    if matches!(steer, Steer::Command(Operation::Reset { .. })) {
        // Asked only of a node it can be issued to.
        let hub = ui.hub.clone();
        let node = id.to_string();
        let row = blocking(move || hub.db.node(&node)).await?;
        let Some(row) = row else {
            return Ok(actions::refused(
                htmx,
                StatusCode::NOT_FOUND,
                "There is no such node.",
            ));
        };
        if let Err(e) = crate::store::steerable(id, &row) {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {e:#}."),
            ));
        }
        let back = format!("/node/{id}");
        let ask = actions::Ask {
            path: format!("{back}/action"),
            back,
            op: "reset".into(),
            what: "Reset this node? It drains, stops what its past jobs left running, and \
                   deletes their job directories and its idle host checkouts.",
            detail: Html::new(),
            asked: Vec::new(),
        };
        if let Some(asked) = actions::ask_first(&site.questions, layout, htmx, &auth, &form, &ask)?
        {
            return Ok(asked);
        }
    }
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
    Ok(said_so(&said))
}

/// For htmx, `said` in the flash, swapped in on its own: the live fragment follows the change.
pub(super) fn said_so(said: &str) -> Response<Body> {
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">")
        .text(said)
        .raw("</div>");
    actions::swap_none(super::html_response(StatusCode::OK, h))
}

/// `/rollout/<id>/action`'s rollout, if `path` is that for a well-formed ID.
pub(super) fn action_rollout(path: &str) -> Option<&str> {
    path.strip_prefix("/rollout/")?
        .strip_suffix("/action")
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// `POST /rollout/<id>/action`: pause, resume or abort as the operator session's principal,
/// using the admin socket's operation. Like node actions, return a status message for htmx
/// or redirect to `/operations`.
pub(super) async fn rollout_action(
    req: Request<Incoming>,
    ui: &Ui,
    id: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let action = match field(&form, "op") {
        Some("pause") => RolloutAction::Pause,
        Some("resume") => RolloutAction::Resume,
        Some("abort") => RolloutAction::Abort,
        _ => {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                "No such action.",
            ));
        }
    };
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    let rollout = id.to_string();
    let done = blocking(move || {
        // The full ID, as the page names it: a prefix is the CLI's convenience.
        if hub.db.rollout(&rollout)?.is_none() {
            return Ok(None);
        }
        Ok(Some(ops::steer_rollout(&hub, &principal, &rollout, action)))
    })
    .await?;
    let said = match done {
        None => {
            return Ok(actions::refused(
                htmx,
                StatusCode::NOT_FOUND,
                "There is no such rollout.",
            ));
        }
        Some(Ok(r)) => format!(
            "Rollout {} is {}.",
            crate::rollout::short_id(&r.id),
            r.row.state.name()
        ),
        Some(Err(e)) if e.is::<RolloutConflict>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {e:#}."),
            ));
        }
        Some(Err(e)) => return Err(e),
    };
    if !htmx {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::SEE_OTHER;
        resp.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static("/operations"));
        return Ok(resp);
    }
    Ok(said_so(&said))
}

/// The page around `main`, with the fleet's navigation.
pub(super) fn layout(title: &str, here: &str, auth: &Auth, main: &Html) -> Html {
    pages::frame(title, here, auth, nav(auth), main)
}

/// The fleet's navigation for `auth`'s session: an operator's has the users page too.
fn nav(auth: &Auth) -> pages::Nav {
    if auth.session.role >= Role::Operator {
        OPERATOR_NAV
    } else {
        NAV
    }
}

const NAV: pages::Nav = &[
    ("/", "Nodes"),
    (super::jobs::PATH, "Jobs"),
    ("/operations", "Operations"),
    ("/audit", "Audit"),
];

const OPERATOR_NAV: pages::Nav = &[
    ("/", "Nodes"),
    (super::jobs::PATH, "Jobs"),
    ("/operations", "Operations"),
    ("/audit", "Audit"),
    (super::users::PATH, "Users"),
];

/// `/`: the nodes table.
fn nodes(auth: &Auth, nodes: &[NodeView], now: u64) -> Html {
    let mut main = Html::new();
    main.raw("<h1>Nodes</h1>")
        .raw("<div id=\"nodes\" hx-ext=\"sse\" sse-connect=\"/events/nodes\" sse-swap=\"nodes\" sse-close=\"close\">")
        .html(&nodes_table(nodes, now))
        .raw("</div>");
    if auth.session.role >= Role::Operator {
        token_form(&mut main, auth);
    }
    layout("Nodes", "/", auth, &main)
}

/// An operator's enrollment form, outside the live fragment. A plain POST returns the token
/// on its own page so it is not sent to every viewer in a shared fragment.
fn token_form(h: &mut Html, auth: &Auth) {
    h.raw("<section><h2>Enroll a node</h2><form method=\"post\" action=\"")
        .raw(TOKEN_PATH)
        .raw("\">");
    pages::csrf_field(h, auth);
    h.raw("<label>Valid for <select name=\"ttl\">");
    for (secs, label) in TOKEN_TTLS {
        h.raw("<option value=\"")
            .text(secs.to_string())
            .raw("\">")
            .text(label)
            .raw("</option>");
    }
    h.raw("</select></label>")
        .raw("<button class=\"primary\">Issue an enrollment token</button></form>")
        .raw("<p class=\"sub\">Single-use: the node redeems it with <code>vk node join</code>, ")
        .raw("which pins the node's key. Shown a single time.</p></section>");
}

/// `POST /tokens`: issue a single-use enrollment token, audited as the operator's session
/// principal. Show it once with redemption instructions; store only its hash and never log it.
pub(super) async fn create_token(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(message(status, text)),
    };
    let Some(ttl) = field(&form, "ttl")
        .and_then(|t| t.parse::<u64>().ok())
        .filter(|t| TOKEN_TTLS.iter().any(|(secs, _)| secs == t))
    else {
        return Ok(message(
            StatusCode::BAD_REQUEST,
            "Refused: not one of the form's lifetimes.",
        ));
    };
    let (hub, principal) = (ui.hub.clone(), auth.session.principal());
    let (token, expires_at) = blocking(move || {
        hub.db.create_token(
            std::time::Duration::from_secs(ttl),
            &principal,
            crate::now_secs(),
        )
    })
    .await?;
    eprintln!(
        "vk-hub: ui: {} issued an enrollment token valid for {ttl}s",
        auth.session.principal()
    );
    let mut main = Html::new();
    main.raw("<h1>Enrollment token</h1><p>Single-use, valid until ");
    pages::at(&mut main, expires_at)
        .raw(". It is shown this once: copy it now.</p><pre>")
        .text(&token)
        .raw("</pre><p>On the node, as root, run this, then paste the token and press Enter ")
        .raw("(it is read on stdin): it sets the host up for ")
        .raw("the user the node runs as — created if need be, given <code>/dev/kvm</code> and ")
        .raw("the state dir — enrolls it, and runs the node as a service:</p><pre>");
    let url = |h: &mut Html| {
        match &ui.hub.node_url {
            Some(url) => h.text(url),
            None => h.raw("&lt;hub-url&gt;"),
        };
    };
    main.raw("vk node join ");
    url(&mut main);
    main.raw(" --token - --user gitlab-runner --service</pre>")
        .raw("<p class=\"sub\">Add <code>--replace</code> for a host already enrolled: its old ")
        .raw("identity is moved aside and <code>join</code> prints the old node's ID, to ")
        .raw("remove with <code>vk-hub nodes remove &lt;id&gt;</code> on the hub. As the user ")
        .raw("itself, without root: ")
        .raw("<code>vk node join ");
    url(&mut main);
    main.raw(" --token -</code>, then <code>vk node service install</code>. Read on stdin, ")
        .raw("the token stays out of the shell's history and the process list.</p>")
        .raw("<p><a href=\"/\">Back to the nodes</a></p>");
    Ok(page(layout("Enrollment token", "/", &auth, &main)))
}

// Columns with custom rendering in `vk-hub nodes` and `vk workloads` (a node's VMs
// here, the host's in local mode). Name checks make a reordering fail to build.
const NODE_ID: usize = 0;
const NODE_NAME: usize = 1;
const NODE_REACH: usize = 2;
const NODE_STATE: usize = 3;
const NODE_SYNC: usize = 7;
const NODE_LAST_SEEN: usize = 8;
const NODE_VK: usize = 9;
pub(super) const VM_KIND: usize = 0;
pub(super) const VM_ID: usize = 1;
pub(super) const VM_FOR: usize = 2;
pub(super) const VM_PID: usize = 3;
const VM_RESERVED: usize = 5;
const VM_IN_USE: usize = 6;
pub(super) const VM_STARTED: usize = 7;
const _: () = {
    let nodes = &crate::NODE_COLUMNS;
    assert!(column_is(nodes, NODE_ID, "ID") && column_is(nodes, NODE_NAME, "NAME"));
    assert!(column_is(nodes, NODE_REACH, "REACH"));
    assert!(column_is(nodes, NODE_STATE, "STATE") && column_is(nodes, NODE_SYNC, "SYNC"));
    assert!(column_is(nodes, NODE_LAST_SEEN, "LAST SEEN") && column_is(nodes, NODE_VK, "VK"));
    let vms = &crate::workloads::COLUMNS;
    assert!(column_is(vms, VM_KIND, "KIND") && column_is(vms, VM_ID, "ID"));
    assert!(column_is(vms, VM_FOR, "FOR"));
    assert!(column_is(vms, VM_PID, "PID") && column_is(vms, 4, "CPUS"));
    assert!(column_is(vms, VM_RESERVED, "RESERVED") && column_is(vms, VM_IN_USE, "IN USE"));
    assert!(column_is(vms, VM_STARTED, "STARTED"));
};

/// The badge opening a node's reach: up or down.
fn reach_badge(connected: bool) -> &'static str {
    if connected {
        "<span class=\"badge ok\">"
    } else {
        "<span class=\"badge bad\">"
    }
}

/// The badge opening a node's state, coloured by where it stands: in service, out of it for
/// a while, under maintenance, or taken out until an operator says otherwise.
fn state_badge(v: &NodeView) -> &'static str {
    use vk_hub_proto::NodeState;
    if v.monitoring_only() {
        return "<span class=\"badge\">";
    }
    match v.report.as_ref().and_then(|r| r.state) {
        Some(NodeState::Ready) => "<span class=\"badge ok\">",
        Some(NodeState::Draining | NodeState::Drained) => "<span class=\"badge warn\">",
        Some(NodeState::Maintenance | NodeState::Validating) => "<span class=\"badge busy\">",
        Some(NodeState::Quarantined) => "<span class=\"badge bad\">",
        None => "<span class=\"badge\">",
    }
}

/// The nodes table, with the columns of `vk-hub nodes`.
fn nodes_table(nodes: &[NodeView], now: u64) -> Html {
    let mut h = Html::new();
    if nodes.is_empty() {
        h.raw("<p class=\"empty\">No node has enrolled yet: an operator issues a token for ")
            .raw("<code>vk node join</code> below, or with <code>vk-hub token create</code>.</p>");
        return h;
    }
    h.raw("<table class=\"grid\"><thead><tr>");
    header_cells(&mut h, &crate::NODE_COLUMNS);
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
        for (i, (cell, column)) in cells.iter().zip(crate::NODE_COLUMNS).enumerate() {
            open_cell(&mut h, column);
            match i {
                // The ID, short, and the name, both leading to the node's page; the ID is
                // one the hub issued and the router checks as hex.
                NODE_ID | NODE_NAME => {
                    h.raw("<a href=\"/node/").text(&n.id).raw("\">");
                    if i == NODE_ID {
                        h.raw("<code>")
                            .text(n.id.get(..8).unwrap_or(&n.id))
                            .raw("</code>");
                    } else {
                        h.node(cell);
                    }
                    h.raw("</a>");
                }
                NODE_REACH => {
                    h.raw(reach_badge(n.connected)).text(cell).raw("</span>");
                }
                // What the node sent: its state, its version and the one it is updating to.
                NODE_STATE => {
                    h.raw(state_badge(n)).node(cell).raw("</span>");
                }
                NODE_VK => {
                    h.node(cell);
                }
                NODE_LAST_SEEN => {
                    match n.last_seen {
                        Some(t) => pages::time(&mut h, t, cell),
                        None => h.text(cell),
                    };
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
    let csrf = steer_token(auth);
    if csrf.is_some() && !detail.view.monitoring_only() {
        // Outside the live fragment, so an update never clears what an action said.
        main.raw("<div id=\"flash\"></div>");
    }
    main.raw("<div id=\"detail\" hx-ext=\"sse\" sse-connect=\"/events/node/")
        .text(id)
        .raw("\" sse-swap=\"node\" sse-close=\"close\">")
        .html(&node_detail(detail, now, csrf))
        .raw("</div>");
    layout(&detail.view.hostname, "/", auth, &main)
}

/// The session's CSRF token for node actions, or `None` to omit unauthorized controls.
fn steer_token(auth: &Auth) -> Option<&str> {
    (auth.session.role >= Role::Operator).then_some(auth.csrf.as_str())
}

/// One action of a node page's steering panel: its `op`, its button, and what it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Act {
    op: &'static str,
    label: &'static str,
    does: &'static str,
}

const PAUSE: Act = Act {
    op: "stop",
    label: "Pause intake",
    does: "Take no new jobs; the running ones finish.",
};
const RESUME: Act = Act {
    op: "resume",
    label: "Resume intake",
    does: "Take new jobs again.",
};
const LIFT: Act = Act {
    op: "lift-ceiling",
    label: "Remove the limit",
    does: "Let the node decide how many jobs it runs at once.",
};
const DRAIN: Act = Act {
    op: "drain",
    label: "Drain",
    does: "Finish the running jobs and take no new ones, for maintenance.",
};
const STAY_DRAINED: Act = Act {
    op: "drain",
    label: "Stay drained",
    does: "Keep the node drained once the update or reset ends.",
};
const UNDRAIN: Act = Act {
    op: "undrain",
    label: "Undrain",
    does: "Back in service: take jobs again.",
};
const QUARANTINE: Act = Act {
    op: "quarantine",
    label: "Quarantine",
    does: "Take the node out of service until it is released: no jobs, no updates, no \
           resets. For a node you no longer trust.",
};
const RELEASE: Act = Act {
    op: "release",
    label: "Release",
    does: "Return the node to service, drained if it was drained before.",
};
const RESET: Act = Act {
    op: "reset",
    label: "Reset",
    does: "Drain, stop what past jobs left running, and delete their job directories and \
           the idle checkouts. Asked again first.",
};

/// A node page's steering, by group: where the node stands on each thing an operator
/// steers, and the actions that apply from there. Every action posts to the same route
/// whatever is offered: the hub and the node refuse what does not apply, as they would from
/// `vk-hub nodes`; the panel offers what makes sense now.
struct Panel {
    /// Why some of the node's steering does not apply, if it does not.
    note: Option<&'static str>,
    intake: String,
    intake_acts: Vec<Act>,
    limit: String,
    lift: Option<Act>,
    maintenance: &'static str,
    maintenance_acts: Vec<Act>,
    danger_acts: Vec<Act>,
}

impl Panel {
    fn of(v: &NodeView) -> Panel {
        use vk_hub_proto::NodeState;
        let report = v.report.as_ref();
        let state = report.and_then(|r| r.state);
        let external = report.and_then(|r| r.runner) == Some(RunnerMode::External);
        let paused = v
            .desired
            .as_ref()
            .is_some_and(|d| d.acquisition == Acquisition::Stop);
        let ceiling = v.desired.as_ref().and_then(|d| d.ceiling);
        let effective = report.and_then(|r| r.concurrency).and_then(|c| c.effective);

        let stopped = match state {
            _ if paused => Some(": intake paused"),
            Some(NodeState::Ready) | None => None,
            Some(NodeState::Draining) => Some(" while draining"),
            Some(NodeState::Drained) => Some(" while drained"),
            Some(NodeState::Maintenance) => Some(" while under maintenance"),
            Some(NodeState::Validating) => Some(" while checking itself"),
            Some(NodeState::Quarantined) => Some(" while quarantined"),
        };
        let intake = match stopped {
            None => "Taking new jobs".to_string(),
            // Pausing intake of the hub's jobs does not stop the external runner.
            Some(why) if external => {
                format!("Not taking the hub's jobs{why}; the external runner may still take jobs")
            }
            Some(why) => format!("Not taking new jobs{why}"),
        };
        let intake_acts = if paused { vec![RESUME] } else { vec![PAUSE] };
        let mut limit = match ceiling {
            Some(n) => format!("Max concurrent jobs: {n}"),
            None => "Max concurrent jobs: no limit from the hub".to_string(),
        };
        if let Some(n) = effective {
            limit.push_str(&format!(" (running at most {n} now)"));
        }

        let maintenance = match state {
            None => "State not reported yet",
            Some(NodeState::Ready) => "In service",
            Some(NodeState::Draining) if external => {
                "Draining: finishing the hub's jobs here, taking none of them"
            }
            Some(NodeState::Draining) => "Draining: finishing its running jobs, taking no new ones",
            Some(NodeState::Drained) if external => "Drained: none of the hub's jobs running here",
            Some(NodeState::Drained) => "Drained: no jobs running, none taken",
            Some(NodeState::Maintenance) => "Under maintenance: an update or a reset is under way",
            Some(NodeState::Validating) => "Checking itself after maintenance",
            Some(NodeState::Quarantined) if external => {
                "Quarantined: taking none of the hub's jobs until released"
            }
            Some(NodeState::Quarantined) => "Quarantined: out of service until released",
        };
        let maintenance_acts = match state {
            None => vec![DRAIN, UNDRAIN],
            Some(NodeState::Ready) => vec![DRAIN],
            Some(NodeState::Maintenance | NodeState::Validating) => vec![STAY_DRAINED],
            Some(NodeState::Draining | NodeState::Drained) => vec![UNDRAIN],
            Some(NodeState::Quarantined) => Vec::new(),
        };
        // Refuse resets with an external runner: it may still use what a reset deletes.
        let mut danger_acts = match state {
            Some(NodeState::Quarantined) => vec![RELEASE],
            None => vec![QUARANTINE, RELEASE],
            Some(_) => vec![QUARANTINE],
        };
        if !external
            && matches!(
                state,
                None | Some(NodeState::Ready | NodeState::Draining | NodeState::Drained)
            )
        {
            danger_acts.push(RESET);
        }
        Panel {
            note: external.then_some(
                "Its runner is external: pausing intake, draining and quarantining stop only \
                 the jobs the hub places here; the runner may still take jobs. A reset is \
                 refused.",
            ),
            intake,
            intake_acts,
            limit,
            lift: ceiling.map(|_| LIFT),
            maintenance,
            maintenance_acts,
            danger_acts,
        }
    }

    /// Every action offered, in the panel's order, the limit's own form first.
    #[cfg(test)]
    fn ops(&self) -> Vec<&'static str> {
        std::iter::once("ceiling")
            .chain(self.intake_acts.iter().map(|a| a.op))
            .chain(self.lift.iter().map(|a| a.op))
            .chain(self.maintenance_acts.iter().map(|a| a.op))
            .chain(self.danger_acts.iter().map(|a| a.op))
            .collect()
    }
}

/// Show the node's state and, given an operator's `csrf`, applicable actions with explanations.
/// Viewers see only the state. The live fragment keeps actions current; `hx-preserve` keeps
/// the limit input through updates, including edits in progress. Forms support htmx and plain
/// submission.
fn steer_panel(h: &mut Html, v: &NodeView, csrf: Option<&str>) {
    let p = Panel::of(v);
    let path = format!("/node/{}/action", v.id);
    let act = |h: &mut Html, a: &Act, class: &'static str| {
        let Some(csrf) = csrf else { return };
        form_open(h, &path, csrf);
        h.raw("<input type=\"hidden\" name=\"op\" value=\"")
            .raw(a.op)
            .raw("\"><button")
            .raw(class)
            .raw(">")
            .raw(a.label)
            .raw("</button><span class=\"does\">")
            .raw(a.does)
            .raw("</span></form>");
    };
    h.raw("<section class=\"steer\"><h2>Steering</h2>");
    if let Some(note) = p.note {
        h.raw("<p class=\"sub\">").raw(note).raw("</p>");
    }
    h.raw("<div class=\"groups\"><div class=\"group\"><h3>Job intake</h3><p class=\"now\">")
        .text(&p.intake)
        .raw("</p>");
    for a in &p.intake_acts {
        act(h, a, "");
    }
    h.raw("<p class=\"now\">").text(&p.limit).raw("</p>");
    if let Some(csrf) = csrf {
        // No placeholder: hx-preserve would keep the first render's, stale after a change.
        form_open(h, &path, csrf);
        h.raw("<input type=\"hidden\" name=\"op\" value=\"ceiling\">")
            .raw("<label for=\"ceiling\">Max concurrent jobs</label>")
            .raw("<input id=\"ceiling\" type=\"number\" name=\"ceiling\" min=\"1\" required ")
            .raw("hx-preserve=\"true\"><button>Set the limit</button><span class=\"does\">")
            .raw("Run at most this many jobs at once on this node.</span></form>");
    }
    if let Some(a) = &p.lift {
        act(h, a, "");
    }
    h.raw("</div><div class=\"group maintenance\"><h3>Maintenance</h3><p class=\"now\">")
        .raw(p.maintenance)
        .raw("</p>");
    for a in &p.maintenance_acts {
        act(h, a, "");
    }
    h.raw("</div>");
    if csrf.is_some() && !p.danger_acts.is_empty() {
        h.raw("<div class=\"group danger\"><h3>Danger zone</h3>");
        for a in &p.danger_acts {
            act(h, a, " class=\"danger\"");
        }
        h.raw("</div>");
    }
    h.raw("</div></section>");
}

/// The opening of a steering form posting to `path`, by htmx or as a plain form, with the
/// session's CSRF token `csrf`.
fn form_open(h: &mut Html, path: &str, csrf: &str) {
    h.raw("<form class=\"act\" method=\"post\" action=\"")
        .text(path)
        .raw("\" hx-post=\"")
        .text(path)
        .raw("\" hx-swap=\"none\">");
    pages::csrf_input(h, csrf);
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

/// The instant `then` as a [`pages::time`], with its [`age`] at `now` as fallback text.
fn time_ago(h: &mut Html, now: u64, then: u64) -> &mut Html {
    pages::time(h, then, &age(now, then))
}

/// [`time_ago`] as a standalone fragment.
fn time_ago_html(now: u64, then: u64) -> Html {
    let mut h = Html::new();
    time_ago(&mut h, now, then);
    h
}

/// A node page's fragment once the node has been removed.
fn gone() -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"empty\">This node has been removed from the hub.</p>");
    h
}

/// A node's page below its name: everything the hub knows of it, and its steering panel,
/// with its actions given `csrf`, an operator's token.
fn node_detail(d: &NodeDetail, now: u64, csrf: Option<&str>) -> Html {
    let v = &d.view;
    let mut h = Html::new();
    h.raw("<p class=\"sub\"><code>")
        .text(&v.id)
        .raw("</code> · ")
        .raw(reach_badge(v.connected))
        .raw(if v.connected {
            "connected"
        } else {
            "unreachable"
        })
        .raw("</span> · last seen ");
    match v.last_seen {
        Some(t) => time_ago(&mut h, now, t),
        None => h.raw("never"),
    };
    h.raw("</p>");

    if !v.monitoring_only() {
        steer_panel(&mut h, v, csrf);
    }
    steering(&mut h, d, now);

    let heartbeat = d.row.heartbeat.as_ref();
    section(&mut h, "Load");
    if let Some(why) = &v.last_refusal {
        kv_node(&mut h, "Refuses reservations", why);
    }
    match heartbeat {
        None => kv(&mut h, "Heartbeat", "none yet"),
        Some(hb) => {
            if let Some(at) = d.row.heartbeat_at {
                kv_html(&mut h, "Heartbeat", &time_ago_html(now, at));
            }
            match &hb.admission {
                Some(a) => {
                    kv(
                        &mut h,
                        "Admitted memory",
                        &format!(
                            "{} of {}",
                            mib(a.committed_mib),
                            a.budget_mib.map_or_else(|| "no budget".to_string(), mib)
                        ),
                    );
                    kv(
                        &mut h,
                        "Jobs",
                        &format!("{} admitted, {} waiting", a.running, a.waiting),
                    );
                }
                None => kv(&mut h, "Admission", "unreadable"),
            }
            kv(
                &mut h,
                "Memory available",
                &hb.mem_available_mib
                    .map_or_else(dash, |m| rough_bytes(m.saturating_mul(1 << 20))),
            );
            kv(
                &mut h,
                "Concurrency asked of the runner",
                &count(hb.desired_concurrency),
            );
        }
    }
    end_section(&mut h);

    workloads(&mut h, d.workloads.as_ref());

    let inventory = d.row.inventory.as_ref();
    section(&mut h, "Hardware");
    match inventory {
        None => kv(&mut h, "Inventory", "none yet"),
        Some(inv) => {
            let hw = &inv.hardware;
            kv(&mut h, "CPUs", &hw.cpus.to_string());
            kv_node(&mut h, "CPU model", hw.cpu_model.as_deref().unwrap_or("-"));
            kv(&mut h, "Memory", &hw.mem_total_mib.map_or_else(dash, mib));
            for m in &hw.memory_nodes {
                kv(
                    &mut h,
                    &format!("memory node {}", m.id),
                    &format!("{} CPUs, {}", m.cpus, mib(m.mem_total_mib)),
                );
            }
            for c in &hw.checks {
                h.raw("<tr><th>Check ").node(&c.name).raw("</th><td>");
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
            "vk sha256",
            inv.versions.vk_sha256.as_deref().unwrap_or("-"),
        );
        kv_node(
            &mut h,
            "Guest kernel",
            inv.versions.guest_kernel.as_deref().unwrap_or("-"),
        );
        kv_node(&mut h, "Configuration hash", &inv.versions.config_hash);
        end_section(&mut h);

        section(&mut h, "Runner");
        match &inv.runner {
            None => kv(&mut h, "Configuration", "unreadable"),
            Some(r) => {
                kv_node(&mut h, "Configuration", &r.config);
                kv(&mut h, "Concurrent", &count(r.concurrent));
                h.raw("<tr><th>Runners</th><td>");
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
            "Steering",
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
            "Desired state",
            "nothing asked: no ceiling, acquisition running",
        ),
        Some(desired) => {
            kv(h, "Generation", &desired.generation.to_string());
            kv(h, "Ceiling", &count(desired.ceiling));
            kv(
                h,
                "Acquisition",
                crate::acquisition_name(desired.acquisition),
            );
        }
    }
    kv(h, "Sync", &crate::node_cells(v, now)[NODE_SYNC]);
    end_section(h);

    section(h, "Reported by the node");
    match &v.report {
        None => kv(h, "Report", "none yet"),
        Some(r) => {
            let or_dash = |s: Option<&str>| s.unwrap_or("-").to_string();
            kv(
                h,
                "Applied generation",
                &r.applied_generation().map_or_else(dash, |g| g.to_string()),
            );
            kv(h, "State", &or_dash(r.state.map(crate::store::state_name)));
            kv(
                h,
                "Acquisition",
                &or_dash(r.acquisition.map(crate::acquisition_name)),
            );
            kv(
                h,
                "Runner",
                &or_dash(r.runner.map(|m| match m {
                    RunnerMode::Managed => "managed",
                    RunnerMode::External => "external",
                })),
            );
            if let Some(state) = r.runner_state {
                kv(
                    h,
                    "Runner process",
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
                    "Concurrency",
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
                    "Drain",
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
                kv_node(h, "Cannot comply", note);
            }
            if let Some(e) = &r.concurrency_error {
                kv_node(h, "Cannot set its concurrency", e);
            }
            if let Some(u) = &r.update {
                h.raw("<tr><th>Update</th><td>vk ")
                    .node(&u.version)
                    .raw(" (<code>")
                    .node(crate::store::short(&u.sha256))
                    .raw("</code>): ")
                    .raw(crate::store::update_phase_name(u.phase));
                if let Some(message) = &u.message {
                    h.raw(": ").node(message);
                }
                h.raw("</td></tr>");
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
            h.raw("<tr><td>");
            pages::at(h, c.issued_at)
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
            h.raw("</td><td>");
            pages::at(h, c.command.expires_at).raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    // The node's ID: the router took it as hex.
    h.raw("<p><a href=\"/audit?node=")
        .text(&d.view.id)
        .raw("\">The node's audit log</a> · <a href=\"/jobs?node=")
        .text(&d.view.id)
        .raw("\">Its jobs</a></p></section>");
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
    header_cells(h, &crate::workloads::COLUMNS);
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
        for (i, (cell, column)) in cells.iter().zip(crate::workloads::COLUMNS).enumerate() {
            open_cell(h, column);
            match i {
                VM_STARTED => match w.started_at {
                    Some(t) => pages::time(h, t, cell),
                    None => h.text(cell),
                },
                // Of the hub's making: the kind's name and the figures.
                VM_KIND | VM_PID..VM_STARTED => h.text(cell),
                VM_ID => h.raw("<code>").node(cell).raw("</code>"),
                // A CI job, leading to its page on GitLab where the node named one fit to be
                // a link.
                VM_FOR if w.kind == WorkloadKind::CiJob => {
                    h.external_link(w.job_url.as_deref(), cell)
                }
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

/// `/operations`: the releases the hub holds and its latest rollouts, kept live.
///
/// The live fragment is rendered once for every viewer and once for every operator
/// ([`sse::feed`]), so it carries no session's CSRF token: an operator's page sets it around
/// the fragment as a header on every htmx request from inside it (`hx-headers`), which is how
/// the rollouts' buttons post. Those buttons need htmx; `vk-hub rollout pause|resume|abort`
/// does the same without it. An operator's page carries the forms that add a release and start
/// a rollout above it.
fn operations(auth: &Auth, ops: &Operations, nodes: &[NodeView], now: u64) -> Html {
    let steer = auth.session.role >= Role::Operator;
    let mut main = Html::new();
    main.raw("<h1>Operations</h1>");
    if steer {
        operations::forms(&mut main, auth, &ops.releases, nodes, ops.source.as_deref());
        // The hub derives the hex token; htmx parses the header's JSON without evaluating it.
        main.raw("<div id=\"flash\"></div><div hx-headers=\"{&quot;X-CSRF-Token&quot;:&quot;")
            .text(&auth.csrf)
            .raw("&quot;}\">");
    }
    main.raw("<div id=\"operations\" hx-ext=\"sse\" sse-connect=\"/events/operations\" ")
        .raw("sse-swap=\"operations\" sse-close=\"close\">")
        .html(&operations_fragment(ops, steer, now))
        .raw("</div>");
    if steer {
        main.raw("</div>");
    }
    layout("Operations", "/operations", auth, &main)
}

/// `/operations`' live part. With `steer`, each rollout still under way carries the buttons
/// that steer it.
fn operations_fragment(ops: &Operations, steer: bool, now: u64) -> Html {
    let mut h = Html::new();
    h.raw("<section><h2>Releases</h2>");
    operations::fetch_line(&mut h, ops.fetch.as_ref(), ops.latest.as_ref());
    if ops.releases.is_empty() {
        h.raw("<p class=\"empty\">none: <code>vk-hub release add</code> copies a vk binary ")
            .raw("into the hub</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>sha256</th><th>version</th>")
            .raw("<th>size</th><th>signed</th><th>added</th><th>by</th></tr></thead><tbody>");
        for r in &ops.releases {
            h.raw("<tr><td><code title=\"")
                .text(&r.sha256)
                .raw("\">")
                .text(crate::store::short(&r.sha256))
                .raw("</code></td><td>")
                .text(&r.row.version)
                .raw("</td><td>")
                .text(bytes(r.row.size))
                .raw("</td><td>")
                .raw(if r.row.signature.is_some() {
                    "yes"
                } else {
                    "no"
                })
                .raw("</td><td>")
                .html(&pages::at_html(r.row.added_at))
                .raw("</td><td>")
                .text(&r.row.added_by)
                .raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section><section><h2>Rollouts</h2>");
    if ops.rollouts.is_empty() {
        h.raw("<p class=\"empty\">none yet: <code>vk-hub rollout create</code> starts one</p>");
    }
    for r in &ops.rollouts {
        rollout(&mut h, r, steer, now);
    }
    h.raw("</section>");
    h
}

/// One rollout: what it updates to and how, its state, and each node by wave.
fn rollout(h: &mut Html, r: &Rollout, steer: bool, now: u64) {
    let row = &r.row;
    h.raw("<div class=\"rollout\"><h3><code>")
        .text(crate::rollout::short_id(&r.id))
        .raw("</code> vk ")
        .text(&row.version)
        .raw(" <span class=\"state ")
        .raw(row.state.name())
        .raw("\">")
        .raw(row.state.name())
        .raw("</span></h3><p class=\"sub\">");
    let counts: Vec<String> = r
        .counts()
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(name, n)| format!("{n} {name}"))
        .collect();
    h.text(counts.join(", "));
    if let Some(wave) = r.wave().filter(|_| row.state.active()) {
        h.raw(" · wave ").text(wave);
    }
    h.raw(" · release <code>")
        .text(crate::store::short(&row.release))
        .raw("</code> · batches of ")
        .text(row.batch)
        .raw(if row.canary_per_profile {
            " after a canary per profile"
        } else {
            ""
        })
        .raw(" · ")
        .text(row.failures)
        .raw(" of at most ")
        .text(row.max_failures)
        .raw(" failure(s) · started ")
        .html(&pages::at_html(row.created_at))
        .raw(" by ")
        .text(&row.created_by)
        .raw("</p>");
    if let RolloutState::Paused { reason } | RolloutState::Aborted { reason } = &row.state {
        // A failure's reason quotes what a node said.
        h.raw("<p class=\"reason\">").node(reason).raw("</p>");
    }
    if steer && row.state.active() {
        h.raw("<div class=\"actions\">");
        let ops: [(&str, &str); 2] = match row.state {
            RolloutState::Running => [("pause", "Pause"), ("abort", "Abort")],
            _ => [("resume", "Resume"), ("abort", "Abort")],
        };
        let path = format!("/rollout/{}/action", r.id);
        for (op, label) in ops {
            // The ID is one the hub issued, and the router takes only hex for one. No CSRF
            // field: the page around the fragment sets the token as a header.
            h.raw("<form method=\"post\" action=\"")
                .text(&path)
                .raw("\" hx-post=\"")
                .text(&path)
                .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
                .raw(op)
                .raw("\"><button>")
                .raw(label)
                .raw("</button></form>");
        }
        h.raw("</div>");
    }
    h.raw("<table class=\"grid\"><thead><tr><th>wave</th><th>node</th><th>status</th>")
        .raw("<th>profile</th></tr></thead><tbody>");
    for n in &row.nodes {
        h.raw("<tr class=\"")
            .raw(n.status.name())
            .raw("\"><td>")
            .text(n.wave)
            .raw("</td><td>");
        if vk_hub_proto::valid_id(&n.id) {
            h.raw("<a href=\"/node/")
                .text(&n.id)
                .raw("\">")
                .node(&n.hostname)
                .raw("</a>");
        } else {
            h.node(&n.hostname);
        }
        h.raw("</td><td>");
        match &n.status {
            NodeStatus::Pending => {
                h.raw("pending");
            }
            NodeStatus::Skipped { reason } => {
                h.raw("skipped: ").node(reason);
            }
            NodeStatus::Updating { command, since, .. } => {
                h.raw("updating, issued ")
                    .html(&time_ago_html(now, *since))
                    .raw(" (command <code>")
                    .text(command)
                    .raw("</code>)");
            }
            NodeStatus::Succeeded { at } => {
                h.raw("succeeded ").html(&pages::at_html(*at));
            }
            NodeStatus::Failed { reason, .. } => {
                h.raw("failed: ").node(reason);
            }
        }
        h.raw("</td><td>").node(&n.profile).raw("</td></tr>");
    }
    h.raw("</tbody></table></div>");
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::{Concurrency, DesiredState, NodeState, Report};

    use super::*;

    fn view(state: NodeState, runner: RunnerMode, desired: Option<DesiredState>) -> NodeView {
        NodeView {
            desired,
            report: Some(Report {
                state: Some(state),
                runner: Some(runner),
                ..Report::default()
            }),
            ..NodeView::default()
        }
    }

    /// A node's page offers, from each state, the actions that apply there: no drain of a
    /// node draining, no release of one not quarantined, no reset when the runner is external.
    /// With no state reported yet, every state action is offered.
    #[test]
    fn the_steering_panel_offers_what_applies_to_the_node_s_state() {
        use NodeState::*;
        use RunnerMode::{External, Managed};
        let ops = |v: &NodeView| Panel::of(v).ops();
        assert_eq!(
            ops(&NodeView::default()),
            [
                "ceiling",
                "stop",
                "drain",
                "undrain",
                "quarantine",
                "release",
                "reset"
            ]
        );
        for (state, want) in [
            (
                Ready,
                &["ceiling", "stop", "drain", "quarantine", "reset"][..],
            ),
            (
                Draining,
                &["ceiling", "stop", "undrain", "quarantine", "reset"],
            ),
            (
                Drained,
                &["ceiling", "stop", "undrain", "quarantine", "reset"],
            ),
            (Maintenance, &["ceiling", "stop", "drain", "quarantine"]),
            (Validating, &["ceiling", "stop", "drain", "quarantine"]),
            (Quarantined, &["ceiling", "stop", "release"]),
        ] {
            assert_eq!(ops(&view(state, Managed, None)), want, "{state:?}");
        }
        // During maintenance a drain keeps the node drained afterwards, and says so.
        assert_eq!(
            Panel::of(&view(Maintenance, Managed, None)).maintenance_acts[0].label,
            "Stay drained"
        );
        assert_eq!(
            ops(&view(Ready, External, None)),
            ["ceiling", "stop", "drain", "quarantine"]
        );
        let mut unreported = view(Ready, External, None);
        if let Some(r) = unreported.report.as_mut() {
            r.state = None;
        }
        assert_eq!(
            ops(&unreported),
            [
                "ceiling",
                "stop",
                "drain",
                "undrain",
                "quarantine",
                "release"
            ]
        );

        let paused = DesiredState {
            generation: 2,
            ceiling: Some(3),
            acquisition: Acquisition::Stop,
        };
        assert_eq!(
            ops(&view(Ready, Managed, Some(paused.clone()))),
            [
                "ceiling",
                "resume",
                "lift-ceiling",
                "drain",
                "quarantine",
                "reset"
            ]
        );
        assert_eq!(
            ops(&view(Ready, External, Some(paused.clone()))),
            ["ceiling", "resume", "lift-ceiling", "drain", "quarantine"]
        );
    }

    /// Each control says where the node stands in words.
    #[test]
    fn the_steering_panel_says_where_the_node_stands() {
        let paused = DesiredState {
            generation: 2,
            ceiling: Some(3),
            acquisition: Acquisition::Stop,
        };
        let mut v = view(NodeState::Ready, RunnerMode::Managed, Some(paused));
        let p = Panel::of(&v);
        assert_eq!(p.intake, "Not taking new jobs: intake paused");
        assert_eq!(p.limit, "Max concurrent jobs: 3");
        assert_eq!(p.maintenance, "In service");
        assert_eq!(p.note, None);
        v.desired = None;
        if let Some(r) = v.report.as_mut() {
            r.state = Some(NodeState::Drained);
            r.runner = Some(RunnerMode::External);
            r.concurrency = Some(Concurrency {
                effective: Some(2),
                ..Concurrency::default()
            });
        }
        let p = Panel::of(&v);
        assert_eq!(
            p.intake,
            "Not taking the hub's jobs while drained; the external runner may still take jobs"
        );
        assert_eq!(
            p.limit,
            "Max concurrent jobs: no limit from the hub (running at most 2 now)"
        );
        assert_eq!(
            p.maintenance,
            "Drained: none of the hub's jobs running here"
        );
        assert_eq!(
            p.note,
            Some(
                "Its runner is external: pausing intake, draining and quarantining stop only \
                 the jobs the hub places here; the runner may still take jobs. A reset is \
                 refused."
            )
        );
        v.desired = Some(DesiredState {
            generation: 3,
            ceiling: None,
            acquisition: Acquisition::Stop,
        });
        assert_eq!(
            Panel::of(&v).intake,
            "Not taking the hub's jobs: intake paused; the external runner may still take jobs"
        );
    }
}
