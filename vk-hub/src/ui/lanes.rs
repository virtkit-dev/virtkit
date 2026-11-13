//! The capacity policy's page at [`PATH`]: its lanes and production headroom, each edited on
//! its own and saved as a whole policy against the digest the page showed, after a question
//! saying what changes ([`actions::ask_first`]). A policy held since its conversion to lanes
//! stays held through these edits ([`crate::store::Db::edit_capacity_policy_if`]); activating
//! it or replacing the whole policy ends the hold. Each project's page lists the lanes that
//! may run it ([`project_section`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::client::Placement;
use vk_hub_proto::job::Envelope;

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::csrf_field;
use super::{Auth, Body, Ui, actions, blocking, decode_form, field, page};
use crate::jobs::{LiveView, Step};
use crate::policy::{Class, Headroom, Lane, LaneId, LaneProject, Policy};
use crate::server::Hub;
use crate::store::{ConversionNote, PolicyRefused, ProjectView, Role, policy_changes};

/// The lanes' page, and where its edits post.
pub(super) const PATH: &str = "/lanes";

/// The event the live view is swapped in on, and its stream's name under `/events/`.
pub(super) const EVENT: &str = "lanes";

/// The most waiting requests and jobs the live view lists of a lane; the rest are counted.
const MAX_LISTED_WAITING: usize = 50;

/// The capacity page this one replaces, the pages of the tenants before lanes, and both
/// before the navigation had sections: all lead to [`PATH`].
const OLD_PATH: &str = "/capacity";
const OLDER_PATH: &str = "/clients/capacity";
const OLDER_TENANTS: &str = "/clients/tenants/";

/// The largest edit posted: a policy the admin socket takes (64 KiB), as a browser posts it,
/// urlencoded, in the field the question carries.
const MAX_FORM: usize = 6 * 64 * 1024;

/// The edits, as `op` names them.
const SAVE: &str = "save";
const UNMAP: &str = "unmap";
const REMOVE: &str = "remove";
const ADD_HEADROOM: &str = "add";
const ACTIVATE: &str = "activate";
const REPLACE: &str = "replace";

/// Why an edit based on a replaced policy is refused.
const STALE: &str = "the policy changed after this page was shown. Reload the page and try again";

/// The most nodes a page lists a lane's work can go to; the rest are counted.
const MAX_LISTED_TARGETS: usize = 8;

/// Map a page's `path` from before lanes or navigation sections to its current page.
pub(super) fn moved(path: &str) -> Option<String> {
    (path == OLD_PATH
        || path.starts_with("/capacity/")
        || path == OLDER_PATH
        || path.starts_with(OLDER_TENANTS))
    .then(|| PATH.to_string())
}

/// What a page says in place of a policy this hub cannot read.
fn unreadable(h: &mut Html, error: &anyhow::Error) {
    h.raw("<p class=\"message\">")
        .text(format!("{error:#}"))
        .raw("</p>");
}

/// An enrolled node for policy descriptions and pickers. Other pages only pass it back to
/// this module.
pub(super) struct KnownNode {
    id: String,
    /// Display-safe hostname, with a short ID for duplicate or missing hostnames.
    label: String,
    pools: Vec<String>,
}

/// The nodes the hub has enrolled, sorted by label. Reads the database: call off the runtime.
pub(super) fn known_nodes(hub: &Hub) -> Result<Vec<KnownNode>> {
    let mut nodes: Vec<_> = (hub.db.nodes()?.into_iter())
        .map(|(id, row)| KnownNode {
            label: vk_hub_proto::display_safe(&row.hostname),
            id,
            pools: row.pools,
        })
        .collect();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for n in &nodes {
        *seen.entry(n.label.clone()).or_default() += 1;
    }
    for n in &mut nodes {
        if n.label.is_empty() || seen.get(&n.label).is_some_and(|&c| c > 1) {
            n.label = format!("{} ({})", n.label, crate::rollout::short_id(&n.id))
                .trim_start()
                .to_owned();
        }
    }
    nodes.sort_by(|a, b| (&a.label, &a.id).cmp(&(&b.label, &b.id)));
    Ok(nodes)
}

/// Nodes allowed by `lane`: members of its selected pools and nodes, or all supplied nodes
/// for an API key lane selecting nothing.
pub(super) fn resolved<'a>(lane: &Lane, nodes: &'a [KnownNode]) -> Vec<&'a KnownNode> {
    (nodes.iter())
        .filter(|n| lane.allows_node(&n.id, &n.pools))
        .collect()
}

/// What a page says of an API key lane selecting nothing.
const ANY_NODE_OF_THE_JOBS_POOL: &str = "any node of the job's pool";

/// Where `lane`'s work can go, as a page says it, and whether that is no node: the first
/// `limit` nodes resolved, `any node of the job's pool` for an API key lane selecting nothing.
fn runs_on_parts(lane: &Lane, nodes: &[KnownNode], limit: usize) -> (String, bool) {
    if !lane.selects() {
        return (ANY_NODE_OF_THE_JOBS_POOL.to_owned(), false);
    }
    let found = resolved(lane, nodes);
    if found.is_empty() {
        return ("no node".to_owned(), true);
    }
    let shown: Vec<_> = (found.iter())
        .take(limit)
        .map(|n| n.label.as_str())
        .collect();
    let text = match found.len().saturating_sub(limit) {
        0 => shown.join(", "),
        more => format!("{} and {more} more", shown.join(", ")),
    };
    (text, false)
}

/// Where `lane`'s work can go, as a cell: [`runs_on_parts`], marked when it is no node.
pub(super) fn runs_on(h: &mut Html, lane: &Lane, nodes: &[KnownNode]) {
    let (text, none) = runs_on_parts(lane, nodes, MAX_LISTED_TARGETS);
    if none {
        h.raw("<span class=\"bad\">").text(text).raw("</span>");
    } else {
        h.text(text);
    }
}

/// What the hub knows besides the policy, named on the page and offered by its pickers.
#[derive(Default)]
struct Known {
    gitlabs: usize,
    /// Each relay's ID and display-safe hostname.
    relays: Vec<(String, String)>,
    runners: Vec<crate::relays::ReportedRunner>,
    /// Each API key's principal ID and name.
    keys: Vec<(String, String)>,
    nodes: Vec<KnownNode>,
    projects: Vec<ProjectView>,
}

impl Known {
    /// Reads the database: call off the runtime.
    fn read(hub: &Hub) -> Result<Self> {
        let views = crate::relays::views(hub)?;
        let relays = (views.iter())
            .map(|r| (r.id.clone(), vk_hub_proto::display_safe(&r.row.hostname)))
            .collect();
        let runners = crate::relays::reported_runners(&views);
        Ok(Known {
            gitlabs: hub.db.gitlabs()?.len(),
            relays,
            runners,
            keys: (hub.db.api_keys_with_ids()?.into_iter())
                .map(|(id, key)| (id, key.name))
                .collect(),
            nodes: known_nodes(hub)?,
            projects: hub.db.gitlab_projects(None)?,
        })
    }

    fn project_path(&self, gitlab: &str, id: u64) -> Option<&str> {
        (self.projects.iter())
            .find(|p| p.gitlab == gitlab && p.id == id)
            .map(|p| p.row.path.as_str())
            .filter(|p| !p.is_empty())
    }

    /// Lane `id` as its row reads: "Runner 42 app-main", "API key ci-bot", "Other API keys".
    fn label(&self, id: &LaneId) -> String {
        match id {
            LaneId::Runner { gitlab, id } => {
                crate::relays::runner_lane_label(&self.runners, self.gitlabs, gitlab, *id)
            }
            LaneId::Key(principal) => {
                let name = (self.keys.iter())
                    .find(|(p, _)| p == principal)
                    .map_or(principal.as_str(), |(_, name)| name.as_str());
                format!("API key {name}")
            }
            LaneId::Default => "Other API keys".to_owned(),
        }
    }

    /// The projects, and their branches, `lane` may run.
    fn projects_text(&self, lane: &Lane) -> String {
        let Some(projects) = &lane.projects else {
            return if lane.runner.is_some() {
                "any".to_owned()
            } else {
                "-".to_owned()
            };
        };
        if projects.is_empty() {
            return "none".to_owned();
        }
        (projects.iter())
            .map(|p| {
                let name = self
                    .project_path(&p.gitlab, p.id)
                    .map_or_else(|| p.id.to_string(), str::to_owned);
                match &p.branches {
                    None => format!("{name} · all"),
                    Some(b) => format!("{name} · {}", b.join(", ")),
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Lane `id` as a query or form names it: `runner/<gitlab>/<id>`, `key/<principal>` or
/// `default`.
fn lane_param(id: &LaneId) -> String {
    match id {
        LaneId::Runner { gitlab, id } => format!("runner/{gitlab}/{id}"),
        LaneId::Key(principal) => format!("key/{principal}"),
        LaneId::Default => "default".to_owned(),
    }
}

/// The lane [`lane_param`] names, if valid.
fn parse_lane(param: &str) -> Option<LaneId> {
    if param == "default" {
        return Some(LaneId::Default);
    }
    if let Some(rest) = param.strip_prefix("runner/") {
        let (gitlab, id) = rest.split_once('/')?;
        let id = id.parse::<u64>().ok().filter(|&id| id > 0)?;
        return crate::store::valid_gitlab_name(gitlab).then(|| LaneId::Runner {
            gitlab: gitlab.to_owned(),
            id,
        });
    }
    let principal = param.strip_prefix("key/")?;
    (!principal.is_empty() && principal.len() <= 255 && !principal.chars().any(char::is_control))
        .then(|| LaneId::Key(principal.to_owned()))
}

/// The address of lane `id`'s edit form, or of mapping it, for a runner without one.
pub(super) fn edit_href(id: &LaneId) -> String {
    format!(
        "{PATH}?edit={}",
        super::jobs::percent_encode(&lane_param(id))
    )
}

/// What the page reads: the policy, what converting it left to review, what the hub knows,
/// and what each lane holds and has waiting.
struct Shown {
    policy: Result<Policy>,
    note: Option<ConversionNote>,
    known: Known,
    live: LiveView,
}

impl Shown {
    /// Reads the database and the scheduler's state: call off the runtime.
    fn read(hub: &Hub) -> Result<Self> {
        Ok(Shown {
            policy: hub.db.capacity_policy(),
            note: hub.db.capacity_conversion()?,
            known: Known::read(hub)?,
            live: crate::jobs::live_view(hub),
        })
    }
}

/// `GET /lanes[?edit=<lane>]`: the lanes, or one lane's edit form for operators.
pub(super) async fn get(query: Option<&str>, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let shown = blocking(move || Shown::read(&hub)).await?;
    let steer = auth.session.role >= Role::Operator;
    let query = decode_form(query.unwrap_or("").as_bytes());
    let mut main = Html::new();
    let policy = match &shown.policy {
        Ok(policy) => policy,
        Err(e) => {
            main.raw("<h1>Lanes</h1>");
            unreadable(&mut main, e);
            return Ok(page(fleet::layout("Lanes", PATH, auth, &main)));
        }
    };
    let digest = policy.digest()?;
    if steer && let Some(id) = field(&query, "edit").and_then(parse_lane) {
        let title = shown.known.label(&id);
        edit_page(&mut main, &title, &id, policy, &shown.known, auth, &digest);
        return Ok(page(fleet::layout(&title, PATH, auth, &main)));
    }
    let waiting: usize = shown.live.lanes.values().map(|l| l.waiting.len()).sum();
    main.raw("<h1>Lanes</h1><p class=\"sub\">")
        .text(policy.lanes.len())
        .raw(" lanes · ")
        .text(waiting)
        .raw(" waiting · policy ")
        .text(crate::store::short(&digest))
        .raw("</p>");
    if let Some(note) = shown.note.as_ref().filter(|n| n.held()) {
        held_section(&mut main, note, auth, &digest, steer);
    }
    main.raw("<section><h2>Lanes</h2>");
    lanes_table(&mut main, &shown, policy, steer);
    if steer {
        add_section(&mut main, policy, &shown.known);
    }
    main.raw("</section>");
    headroom_section(&mut main, policy, auth, &digest, steer);
    main.raw("<section><h2>Live</h2><div id=\"live\" hx-ext=\"sse\" sse-connect=\"/events/")
        .raw(EVENT)
        .raw("\" sse-swap=\"")
        .raw(EVENT)
        .raw("\" sse-close=\"close\">")
        .html(&live_fragment(&shown, policy, crate::now_secs()))
        .raw("</div><p class=\"sub\">Load per node: <a href=\"/\">Nodes</a>. Delisted and ")
        .raw("finished jobs: <a href=\"")
        .raw(super::jobs::PATH)
        .raw("\">Jobs</a>.</p></section>");
    whole_policy(&mut main, policy, auth, &digest, steer)?;
    Ok(page(fleet::layout("Lanes", PATH, auth, &main)))
}

/// A policy held since its conversion: the rules that did not convert, and its activation.
fn held_section(h: &mut Html, note: &ConversionNote, auth: &Auth, digest: &str, steer: bool) {
    h.raw("<section><h2>Not active</h2><p class=\"message\">No new work starts until this ")
        .raw("policy is activated. Running work continues.</p><p>These placement rules did ")
        .raw("not convert. Set the nodes of their lanes, then activate:</p><ul>");
    for rule in &note.unconverted {
        h.raw("<li>").text(rule).raw("</li>");
    }
    h.raw("</ul>");
    if steer {
        button_form(h, auth, ACTIVATE, digest, &[], "Activate");
    }
    h.raw("</section>");
}

fn lanes_table(h: &mut Html, shown: &Shown, policy: &Policy, steer: bool) {
    if policy.lanes.is_empty() {
        h.raw("<p class=\"empty\">No lanes: no work gets capacity.</p>");
        return;
    }
    let shared: BTreeMap<&LaneId, &str> = (shown.note.iter())
        .flat_map(|n| &n.shared)
        .map(|(id, tenant)| (id, tenant.as_str()))
        .collect();
    h.raw("<table class=\"grid\"><thead><tr><th>lane</th><th>class</th>")
        .raw("<th class=\"num\">weight</th><th class=\"num\">max slots</th><th>runs on</th>")
        .raw("<th>projects · branches</th><th class=\"num\">slots held</th>")
        .raw("<th class=\"num\">waiting</th>");
    if steer {
        h.raw("<th></th>");
    }
    h.raw("</tr></thead><tbody>");
    for lane in &policy.lanes {
        let Some(id) = lane.id() else { continue };
        let live = shown.live.lanes.get(&id);
        let (held, waiting) = live.map_or((0, 0), |l| (l.held, l.waiting.len()));
        h.raw("<tr><td>").text(shown.known.label(&id));
        if let Some(tenant) = shared.get(&id) {
            h.raw("<div class=\"sub\">Took shared tenant ")
                .text(tenant)
                .raw("'s weight and max slots: check them</div>");
        }
        h.raw("</td><td>")
            .text(lane.class)
            .raw("</td><td class=\"num\">")
            .text(lane.weight)
            .raw("</td><td class=\"num\">")
            .text(
                lane.max_slots
                    .map_or_else(|| "-".to_owned(), |n| n.to_string()),
            )
            .raw("</td><td>");
        runs_on(h, lane, &shown.known.nodes);
        h.raw("</td><td>")
            .text(shown.known.projects_text(lane))
            .raw("</td><td class=\"num\">")
            .text(held)
            .raw("</td><td class=\"num\">")
            .text(waiting)
            .raw("</td>");
        if steer {
            h.raw("<td class=\"actions\"><a href=\"")
                .text(edit_href(&id))
                .raw("\">Edit</a></td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// The runners seen without a lane, each to add one for, and the API keys without one, to add.
fn add_section(h: &mut Html, policy: &Policy, known: &Known) {
    let unmapped: Vec<_> = (known.runners.iter())
        .filter(|r| policy.runner(&r.gitlab, r.id).is_none())
        .collect();
    if !unmapped.is_empty() {
        h.raw("<h3>Runners without a lane</h3><p class=\"sub\">Their jobs are refused.")
            .raw("</p><ul>");
        for r in unmapped {
            let id = LaneId::Runner {
                gitlab: r.gitlab.clone(),
                id: r.id,
            };
            h.raw("<li>")
                .text(known.label(&id))
                .raw(" <a href=\"")
                .text(edit_href(&id))
                .raw("\">Add a lane</a></li>");
        }
        h.raw("</ul>");
    }
    let keys: Vec<_> = (known.keys.iter())
        .filter(|(p, _)| policy.lane(&LaneId::Key(p.clone())).is_none())
        .collect();
    if !keys.is_empty() {
        h.raw("<form class=\"wide\" method=\"get\" action=\"")
            .raw(PATH)
            .raw("\"><label>API key <select name=\"edit\">");
        for (principal, name) in keys {
            h.raw("<option value=\"")
                .text(lane_param(&LaneId::Key(principal.clone())))
                .raw("\">")
                .text(name)
                .raw("</option>");
        }
        h.raw("</select></label><button>Add API key lane</button></form>");
    }
}

/// Lane `id`'s edit form, and its unmapping or removal.
fn edit_page(
    h: &mut Html,
    title: &str,
    id: &LaneId,
    policy: &Policy,
    known: &Known,
    auth: &Auth,
    digest: &str,
) {
    let existing = policy.lane(id);
    let lane = existing.cloned().unwrap_or_else(|| Lane::new(id));
    h.raw("<h1>").text(title).raw("</h1>");
    if existing.is_none() {
        h.raw("<p class=\"sub\">No lane yet: saving adds it.</p>");
    }
    edit_form(h, auth, SAVE, digest);
    hidden(h, "lane", lane_param(id));
    if lane.runner.is_some() {
        h.raw("<label>Class <select name=\"class\">");
        for class in [Class::Normal, Class::Production] {
            h.raw("<option")
                .raw(if class == lane.class {
                    " selected>"
                } else {
                    ">"
                })
                .text(class)
                .raw("</option>");
        }
        h.raw("</select></label>");
    }
    h.raw("<label>Weight <input type=\"number\" name=\"weight\" min=\"1\" required value=\"")
        .text(lane.weight)
        .raw("\"></label><label>Max slots <input type=\"number\" name=\"max_slots\" min=\"1\" ")
        .raw("placeholder=\"no limit\" value=\"");
    if let Some(max) = lane.max_slots {
        h.text(max);
    }
    h.raw("\"></label>");
    targets_picker(h, &known.nodes, &lane);
    if let LaneId::Runner { gitlab, .. } = id {
        projects_picker(h, gitlab, &lane, known);
    }
    h.raw("<button>Save</button></form>");
    if existing.is_some() {
        match id {
            LaneId::Runner { .. } => {
                let fields = [("lane", lane_param(id))];
                button_form(h, auth, UNMAP, digest, &fields, "Unmap");
            }
            LaneId::Key(_) => {
                let fields = [("lane", lane_param(id))];
                button_form(h, auth, REMOVE, digest, &fields, "Remove");
            }
            LaneId::Default => {}
        }
    }
    h.raw("<p><a href=\"").raw(PATH).raw("\">Back</a></p>");
}

/// A runner lane's projects: any, or those ticked, each with its branches.
fn projects_picker(h: &mut Html, gitlab: &str, lane: &Lane, known: &Known) {
    let listed = lane.projects.as_ref();
    h.raw("<fieldset class=\"pick\"><legend>Projects</legend><label><input type=\"radio\" ")
        .raw("name=\"projects\" value=\"any\"")
        .raw(if listed.is_none() { " checked" } else { "" })
        .raw("> Any project</label><label><input type=\"radio\" name=\"projects\" ")
        .raw("value=\"listed\"")
        .raw(if listed.is_some() { " checked" } else { "" })
        .raw("> Only those ticked</label><table class=\"grid\"><thead><tr><th></th>")
        .raw("<th>project</th><th>branches</th></tr></thead><tbody>");
    let mut rows: Vec<(u64, Option<&LaneProject>)> = (listed.into_iter().flatten())
        .map(|p| (p.id, Some(p)))
        .collect();
    for p in known.projects.iter().filter(|p| p.gitlab == gitlab) {
        if rows.iter().all(|(id, _)| *id != p.id) {
            rows.push((p.id, None));
        }
    }
    for (id, project) in rows {
        h.raw("<tr><td><input type=\"checkbox\" name=\"project\" value=\"")
            .text(id)
            .raw(if project.is_some() {
                "\" checked"
            } else {
                "\""
            })
            .raw(" aria-label=\"Project ")
            .text(id)
            .raw("\"></td><td>")
            .text(known.project_path(gitlab, id).unwrap_or(""))
            .raw(" <span class=\"sub\">")
            .text(id)
            .raw("</span></td><td><textarea name=\"branches.")
            .text(id)
            .raw("\" rows=\"2\" spellcheck=\"false\" placeholder=\"all\" ")
            .raw("aria-label=\"Branches\">")
            .text(
                project
                    .and_then(|p| p.branches.as_ref())
                    .map(|b| b.join("\n"))
                    .unwrap_or_default(),
            )
            .raw("</textarea></td></tr>");
    }
    h.raw("<tr><td></td><td><input type=\"number\" name=\"project_new\" min=\"1\" ")
        .raw("placeholder=\"project ID\" aria-label=\"Another project\"></td><td>")
        .raw("<textarea name=\"branches.new\" rows=\"2\" spellcheck=\"false\" ")
        .raw("placeholder=\"all\" aria-label=\"Branches\"></textarea></td>")
        .raw("</tr></tbody></table><p class=\"sub\">Branches: one per line, ")
        .raw("<code>*</code> matches any text. A production lane lists its projects, each ")
        .raw("with its branches.</p></fieldset>");
}

/// Checkboxes posting `pools`: known pools with their members, then nodes as implicit pools
/// with their pool memberships. Keep unknown selections ticked so saving preserves them;
/// pools with no nodes can also be typed. Below, show resolved nodes, updated by `checks.js`
/// from each checked box's `data-nodes`.
fn targets_picker(h: &mut Html, known: &[KnownNode], lane: &Lane) {
    /// A checkbox posting `value` as `pools`, resolving to `members`, labelled by what `label`
    /// writes.
    fn tick(
        h: &mut Html,
        value: &str,
        ticked: bool,
        members: &[&str],
        label: impl FnOnce(&mut Html),
    ) {
        h.raw("<label><input type=\"checkbox\" name=\"pools\" value=\"")
            .text(value)
            .raw("\" data-nodes=\"")
            .text(members.join("\n"))
            .raw(if ticked { "\" checked> " } else { "\"> " });
        label(h);
        h.raw("</label>");
    }
    let selected = |t: &str| lane.pools.iter().any(|p| p == t);
    // An empty API key selection leaves each job to its pool.
    h.raw("<fieldset class=\"pick\" data-runs-on=\"");
    if lane.runner.is_none() {
        h.text(ANY_NODE_OF_THE_JOBS_POOL);
    }
    h.raw("\"><legend>Where its work runs</legend>");
    let mut pools: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for n in known {
        for pool in &n.pools {
            pools.entry(pool).or_default().push(&n.label);
        }
    }
    for (pool, members) in &pools {
        tick(h, pool, selected(pool), members, |h| {
            h.text(pool)
                .raw(" <span class=\"sub\">")
                .text(members.join(", "))
                .raw("</span>");
        });
    }
    for n in known {
        let pool = crate::policy::node_pool(&n.id);
        tick(h, &pool, selected(&pool), &[&n.label], |h| {
            h.text(&n.label);
            if !n.pools.is_empty() {
                h.raw(" <span class=\"sub\">")
                    .text(n.pools.join(", "))
                    .raw("</span>");
            }
        });
    }
    for t in &lane.pools {
        if pools.contains_key(t.as_str())
            || crate::policy::node_of_pool(t).is_some_and(|id| known.iter().any(|n| n.id == id))
        {
            continue;
        }
        tick(h, t, true, &[], |h| match crate::policy::node_of_pool(t) {
            Some(id) => {
                h.raw("<code>")
                    .text(id)
                    .raw("</code> <span class=\"sub\">node not enrolled</span>");
            }
            None => {
                h.text(t).raw(" <span class=\"sub\">no node</span>");
            }
        });
    }
    if known.is_empty() && lane.pools.is_empty() {
        h.raw("<span class=\"sub\">No node enrolled yet.</span>");
    }
    h.raw("<label>Another pool <input type=\"text\" name=\"pools\" spellcheck=\"false\" ")
        .raw("aria-label=\"Another pool\"></label><p id=\"runs-on\"");
    let (text, none) = runs_on_parts(lane, known, usize::MAX);
    if none {
        h.raw(" class=\"bad\"");
    }
    h.raw(">Its work can go to: <span>")
        .text(text)
        .raw("</span></p></fieldset>");
    if lane.runner.is_some() {
        h.raw("<p class=\"sub\">A runner's work goes only where its lane selects; selecting ")
            .raw("nothing gives it none.</p>");
    } else {
        h.raw("<p class=\"sub\">A job naming a pool also goes only to that pool's nodes; ")
            .raw("selecting nothing leaves each job to the pool it names.</p>");
    }
}

fn headroom_section(h: &mut Html, policy: &Policy, auth: &Auth, digest: &str, steer: bool) {
    h.raw("<section><h2>Production headroom</h2><p class=\"sub\">Room only production lanes ")
        .raw("may take.</p>");
    if policy.headroom.is_empty() {
        h.raw("<p class=\"empty\">None. Normal work may take all the room.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>pool</th><th>labels</th>")
            .raw("<th>envelope</th><th class=\"num\">slots</th>");
        if steer {
            h.raw("<th></th>");
        }
        h.raw("</tr></thead><tbody>");
        for (i, entry) in policy.headroom.iter().enumerate() {
            let p = &entry.placement;
            h.raw("<tr><td>")
                .text(&p.pool)
                .raw("</td><td>")
                .text(if p.labels.is_empty() {
                    "-".to_owned()
                } else {
                    p.labels.join(", ")
                })
                .raw("</td><td>")
                .text(crate::store::envelope_text(p.envelope))
                .raw("</td><td class=\"num\">")
                .text(entry.slots)
                .raw("</td>");
            if steer {
                h.raw("<td class=\"actions\">");
                let fields = [("headroom", i.to_string())];
                button_form(h, auth, REMOVE, digest, &fields, "Remove");
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    if steer {
        h.raw("<details><summary>Keep room</summary>");
        edit_form(h, auth, ADD_HEADROOM, digest);
        h.raw("<label>Slots <input type=\"number\" name=\"slots\" min=\"1\" value=\"1\" ")
            .raw("required></label><label>Pool <input name=\"pool\" required></label>")
            .raw("<label>Labels <input name=\"labels\" placeholder=\"comma-separated\">")
            .raw("</label><label>Memory <input type=\"number\" name=\"mem_mib\" min=\"1\" ")
            .raw("required> MiB</label><label>CPUs <input type=\"number\" name=\"cpus\" ")
            .raw("min=\"1\" required></label><label>Disk <input type=\"number\" ")
            .raw("name=\"disk_gib\" min=\"0\" value=\"0\" required> GiB</label>")
            .raw("<button>Keep room</button></form></details>");
    }
    h.raw("</section>");
}

/// The whole policy, as `vk-hub capacity-policy show` prints it, and for operators replaced.
fn whole_policy(
    h: &mut Html,
    policy: &Policy,
    auth: &Auth,
    digest: &str,
    steer: bool,
) -> Result<()> {
    let json = serde_json::to_string_pretty(policy)?;
    h.raw("<details><summary>Whole policy</summary><p class=\"sub\">As ")
        .raw("<code>vk-hub capacity-policy show</code> prints it. Probe and backoff settings ")
        .raw("are changed with <code>vk-hub capacity-policy set</code> only.</p>");
    if steer {
        edit_form(h, auth, REPLACE, digest);
        h.raw("<textarea name=\"policy\" rows=\"24\" spellcheck=\"false\" ")
            .raw("aria-label=\"Policy (JSON)\">")
            .text(json)
            .raw("</textarea><button>Replace the policy</button></form>");
    } else {
        h.raw("<pre>").text(json).raw("</pre>");
    }
    h.raw("</details>");
    Ok(())
}

/// The live view's fragment: waiting work per step, the scheduler's last pick, and each lane
/// with work waiting, with why each request or queued job waits.
fn live_fragment(shown: &Shown, policy: &Policy, now: u64) -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"steps\">");
    for (i, step) in Step::ALL.into_iter().enumerate() {
        let waiting = (shown.live.lanes.values())
            .flat_map(|l| &l.waiting)
            .filter(|w| w.step == step)
            .count();
        if i > 0 {
            h.raw(" → ");
        }
        h.raw("<span");
        if step == Step::Reserved {
            h.raw(" title=\"Queued jobs starting on room already granted to them\"");
        }
        h.raw(">")
            .text(step.name())
            .raw(" <strong>")
            .text(waiting)
            .raw("</strong></span>");
    }
    h.raw("</p><p>");
    match &shown.live.last_pick {
        Some(pick) => {
            h.raw("Last pick ");
            super::fleet::time_ago(&mut h, now, pick.at);
            h.raw(": ")
                .text(shown.known.label(&pick.lane))
                .raw(", ")
                .text(pick.step.name())
                .raw(" step, held ÷ weight ")
                .text(share_text(pick.held, pick.weight))
                .raw(".");
        }
        None => {
            h.raw("No pick since the hub started.");
        }
    }
    h.raw("</p>");
    let mut lanes: Vec<_> = (shown.live.lanes.iter())
        .filter(|(_, l)| !l.waiting.is_empty())
        .map(|(id, l)| (id, l, policy.lane(id).map_or(1, |p| p.weight)))
        .collect();
    if lanes.is_empty() {
        h.raw("<p class=\"empty\">Nothing waits.</p>");
        return h;
    }
    // The least held for its weight first, as the scheduler serves lanes within a step.
    lanes.sort_by(|(a, la, wa), (b, lb, wb)| {
        (u128::from(la.held) * u128::from(*wb))
            .cmp(&(u128::from(lb.held) * u128::from(*wa)))
            .then_with(|| a.cmp(b))
    });
    h.raw("<table class=\"grid\"><thead><tr><th>lane</th><th>held ÷ weight</th>")
        .raw("<th>waiting</th></tr></thead><tbody>");
    for (id, lane, weight) in lanes {
        h.raw("<tr><td>")
            .text(shown.known.label(id))
            .raw("</td><td>")
            .text(share_text(lane.held, weight))
            .raw("</td><td><details data-keep=\"")
            .text(lane_param(id))
            .raw("\"><summary>")
            .text(lane.waiting.len())
            .raw(" waiting</summary><ul>");
        for w in lane.waiting.iter().take(MAX_LISTED_WAITING) {
            h.raw("<li>");
            match &w.job {
                Some(job) => {
                    h.raw("<a href=\"")
                        .raw(super::jobs::DETAIL_PREFIX)
                        .text(job)
                        .raw("\">queued job</a>");
                }
                None => {
                    h.raw("request");
                }
            }
            if let Some(relay) = &w.relay {
                let name = (shown.known.relays.iter())
                    .find(|(id, _)| id == relay)
                    .map_or(relay.as_str(), |(_, host)| host.as_str());
                h.raw(" · relay ").text(name);
            }
            if let Some(runner) = &w.runner {
                h.raw(" · ").text(runner);
            }
            h.raw(" · ")
                .text(w.step.name())
                .raw(" · ")
                .text(crate::store::envelope_text(w.envelope))
                .raw(" · ")
                .text(w.waited_secs)
                .raw(" s · ")
                .text(w.reason)
                .raw("</li>");
        }
        if let Some(more) = lane.waiting.len().checked_sub(MAX_LISTED_WAITING)
            && more > 0
        {
            h.raw("<li>and ").text(more).raw(" more</li>");
        }
        h.raw("</ul></details></td></tr>");
    }
    h.raw("</tbody></table>");
    h
}

/// `held ÷ weight = share`, as the live view shows it.
fn share_text(held: u64, weight: u32) -> String {
    let share = held as f64 / f64::from(weight.max(1));
    format!("{held} ÷ {weight} = {share:.1}")
}

/// What `/events/lanes` renders: the live view, as the page shows it.
pub(super) fn live_render(hub: &Arc<Hub>) -> super::sse::Render {
    let hub = hub.clone();
    Arc::new(move || {
        let shown = Shown::read(&hub)?;
        Ok(match &shown.policy {
            Ok(policy) => live_fragment(&shown, policy, crate::now_secs()).into_string(),
            Err(e) => {
                let mut h = Html::new();
                unreadable(&mut h, e);
                h.into_string()
            }
        })
    })
}

/// A form posting `op` to [`PATH`] against the policy of digest `expected`, left open.
fn edit_form(h: &mut Html, auth: &Auth, op: &'static str, expected: &str) {
    edit_form_class(h, auth, op, expected, "wide");
}

fn edit_form_class(
    h: &mut Html,
    auth: &Auth,
    op: &'static str,
    expected: &str,
    class: &'static str,
) {
    h.raw("<form class=\"")
        .raw(class)
        .raw("\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\">");
    csrf_field(h, auth);
    hidden(h, "op", op);
    hidden(h, "expected", expected);
}

fn hidden(h: &mut Html, name: &'static str, value: impl std::fmt::Display) {
    h.raw("<input type=\"hidden\" name=\"")
        .raw(name)
        .raw("\" value=\"")
        .text(value)
        .raw("\">");
}

/// A form of one button `label`, posting `op` with `fields`.
fn button_form(
    h: &mut Html,
    auth: &Auth,
    op: &'static str,
    expected: &str,
    fields: &[(&'static str, String)],
    label: &'static str,
) {
    edit_form_class(h, auth, op, expected, "act");
    for (name, value) in fields {
        hidden(h, name, value);
    }
    h.raw("<button>").raw(label).raw("</button></form>");
}

/// A project's section of its page: the lanes that may run it, by listing it or any project
/// of its instance.
pub(super) fn project_section(
    h: &mut Html,
    policy: &Result<Policy>,
    nodes: &[KnownNode],
    gitlab: &str,
    id: u64,
) {
    h.raw("<section><h2>Lanes</h2>");
    let policy = match policy {
        Ok(policy) => policy,
        Err(e) => {
            unreadable(h, e);
            h.raw("</section>");
            return;
        }
    };
    let lanes: Vec<_> = (policy.lanes.iter())
        .filter(|l| l.runner.as_ref().is_some_and(|r| r.gitlab == gitlab))
        .filter_map(|l| match &l.projects {
            None => Some((l, None)),
            Some(ps) => ps
                .iter()
                .find(|p| p.id == id)
                .map(|p| (l, Some(p.branches.as_ref()))),
        })
        .collect();
    if lanes.is_empty() {
        h.raw("<p class=\"empty\">No lane may run this project's jobs.</p></section>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>lane</th><th>class</th><th>branches</th>")
        .raw("<th>runs on</th></tr></thead><tbody>");
    for (lane, listed) in lanes {
        let branches = match listed {
            None => "all (any project)".to_owned(),
            Some(None) => "all".to_owned(),
            Some(Some(b)) => b.join(", "),
        };
        let name = lane.runner.as_ref().map_or_else(String::new, |r| {
            Known::default().label(&LaneId::Runner {
                gitlab: r.gitlab.clone(),
                id: r.id,
            })
        });
        h.raw("<tr><td>")
            .text(name)
            .raw("</td><td>")
            .text(lane.class)
            .raw("</td><td>")
            .text(branches)
            .raw("</td><td>");
        runs_on(h, lane, nodes);
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table></section>");
}

/// Every value of `name` in `form`, trimmed, without empty ones.
fn values<'a>(form: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> {
    (form.iter())
        .filter(move |(k, _)| k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// Parse `value` as a number; name `what` in the error.
fn number<T: std::str::FromStr>(value: &str, what: &str) -> Result<T> {
    (value.trim().parse().ok()).with_context(|| format!("{what} must be a whole number"))
}

/// `value`'s lines, trimmed, without empty ones; `None` for none. A line, not a comma, ends a
/// pattern: a branch name may hold a comma.
fn branches(value: &str) -> Option<Vec<String>> {
    let list: Vec<String> = (value.lines())
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(str::to_owned)
        .collect();
    (!list.is_empty()).then_some(list)
}

/// `new`, or `old` when it holds the same items: an edit naming the same ones changes nothing.
fn same_or<T: Ord + Clone>(old: Option<&Vec<T>>, new: Vec<T>) -> Vec<T> {
    match old {
        Some(old) if old.iter().collect::<BTreeSet<_>>() == new.iter().collect() => old.clone(),
        _ => new,
    }
}

/// Lane `id` as the form sets it, from `current`'s.
fn lane_from(id: &LaneId, current: Option<&Lane>, form: &[(String, String)]) -> Result<Lane> {
    let value = |name| field(form, name).unwrap_or("");
    let mut lane = current.cloned().unwrap_or_else(|| Lane::new(id));
    lane.weight = number(value("weight"), "the weight")?;
    lane.max_slots = match value("max_slots").trim() {
        "" => None,
        max => Some(number(max, "max slots")?),
    };
    let mut targets: Vec<String> = Vec::new();
    for t in values(form, "pools") {
        if !targets.iter().any(|seen| seen == t) {
            targets.push(t.to_owned());
        }
    }
    lane.pools = same_or(Some(&lane.pools), targets);
    if let LaneId::Runner { gitlab, .. } = id {
        lane.class = match value("class") {
            "normal" => Class::Normal,
            "production" => Class::Production,
            _ => bail!("no such class"),
        };
        lane.projects = match value("projects") {
            "any" => None,
            "listed" => {
                let mut projects = Vec::new();
                let new = value("project_new").trim();
                let ticked = values(form, "project").map(|id| (id, format!("branches.{id}")));
                let added = (!new.is_empty()).then(|| (new, "branches.new".to_owned()));
                for (pid, branches_field) in ticked.chain(added) {
                    let pid: u64 = number(pid, "a project ID")?;
                    if projects.iter().any(|p: &LaneProject| p.id == pid) {
                        continue;
                    }
                    projects.push(LaneProject {
                        gitlab: gitlab.clone(),
                        id: pid,
                        branches: branches(field(form, &branches_field).unwrap_or("")),
                    });
                }
                let old = lane.projects.as_ref();
                // Kept in the order listed before, new ones after.
                let at = |p: &LaneProject| {
                    old.and_then(|o| o.iter().position(|q| q.id == p.id))
                        .unwrap_or(usize::MAX)
                };
                projects.sort_by_key(at);
                Some(projects)
            }
            _ => bail!("choose any project or those ticked"),
        };
    }
    Ok(lane)
}

/// The policy `op` makes of `current` with `form`'s fields, not yet validated.
fn propose(current: &Policy, op: &str, form: &[(String, String)], held: bool) -> Result<Policy> {
    let value = |name| field(form, name).unwrap_or("");
    let lane = || parse_lane(value("lane")).context("no such lane");
    let mut policy = current.clone();
    match op {
        SAVE => {
            let id = lane()?;
            let edited = lane_from(&id, current.lane(&id), form)?;
            match (policy.lanes.iter_mut()).find(|l| l.id().as_ref() == Some(&id)) {
                Some(slot) => *slot = edited,
                None => policy.lanes.push(edited),
            }
        }
        REMOVE if field(form, "headroom").is_some() => {
            let index: usize = number(value("headroom"), "the headroom entry")?;
            if index >= policy.headroom.len() {
                bail!("no such headroom entry");
            }
            policy.headroom.remove(index);
        }
        UNMAP | REMOVE => {
            let id = lane()?;
            if id == LaneId::Default || current.lane(&id).is_none() {
                bail!("no such lane");
            }
            policy.lanes.retain(|l| l.id().as_ref() != Some(&id));
        }
        ADD_HEADROOM => {
            let disk_gib: u64 = number(value("disk_gib"), "the disk")?;
            let headroom = Headroom {
                placement: Placement {
                    pool: value("pool").trim().to_owned(),
                    labels: (value("labels").split([',', ' ']))
                        .filter(|l| !l.is_empty())
                        .map(str::to_owned)
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    envelope: Envelope {
                        mem_mib: number(value("mem_mib"), "the memory")?,
                        cpus: number(value("cpus"), "the CPUs")?,
                        disk_bytes: disk_gib.checked_mul(1 << 30).context("too much disk")?,
                    },
                },
                slots: number(value("slots"), "the slots")?,
            };
            if policy.headroom.contains(&headroom) {
                bail!("this room is kept already");
            }
            policy.headroom.push(headroom);
        }
        ACTIVATE if !held => bail!("the policy is active already"),
        ACTIVATE => {}
        REPLACE => {
            let replaced: Policy =
                serde_json::from_str(value("policy")).context("not a capacity policy")?;
            let settings = |p: &Policy| {
                (
                    p.probe_limit,
                    p.production_probe_burst,
                    p.backoff_initial_secs,
                    p.backoff_max_secs,
                    p.busy_secs,
                )
            };
            if settings(&replaced) != settings(current) {
                bail!("probe and backoff settings are changed with `vk-hub capacity-policy set`");
            }
            return Ok(replaced);
        }
        _ => bail!("no such edit"),
    }
    Ok(policy)
}

/// `POST /lanes`: an edit of the policy, asked first. The question carries the policy the
/// edit proposes, which its answer stores.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post_sized(req, ui, Role::Operator, MAX_FORM).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    // A browser posts a textarea's line breaks as CRLF: read them as LF.
    let form: Vec<(String, String)> = form
        .into_iter()
        .map(|(k, v)| (k, v.replace("\r\n", "\n")))
        .collect();
    let op = match field(&form, "op") {
        Some(op @ (SAVE | UNMAP | REMOVE | ADD_HEADROOM | ACTIVATE | REPLACE)) => op.to_owned(),
        _ => return Ok(refused_page(&auth, StatusCode::BAD_REQUEST, "no such edit")),
    };
    let hub = ui.hub.clone();
    // Confirmation answers need no inventory: the question already showed the warnings.
    let answer = field(&form, "confirm") == Some("yes");
    let read = blocking(move || {
        Ok(hub.db.capacity_policy().and_then(|policy| {
            let note = hub.db.capacity_conversion()?;
            let known = if answer {
                Known::default()
            } else {
                Known::read(&hub)?
            };
            Ok((policy, note, known))
        }))
    });
    let (current, note, known) = match read.await? {
        Ok(read) => read,
        Err(e) => {
            let why = format!("{e:#}");
            return Ok(refused_page(&auth, StatusCode::CONFLICT, &why));
        }
    };
    let expected = field(&form, "expected").unwrap_or("").to_owned();
    if expected != current.digest()? {
        return Ok(refused_page(&auth, StatusCode::CONFLICT, STALE));
    }
    let held = note.as_ref().is_some_and(ConversionNote::held);
    // An answer carries the policy its question proposed.
    let proposed = if answer {
        serde_json::from_str::<Policy>(field(&form, "policy").unwrap_or(""))
            .context("not a capacity policy")
    } else {
        propose(&current, &op, &form, held)
    };
    let proposed = match proposed.and_then(|p| p.validate().map(|()| p)) {
        Ok(proposed) => proposed,
        Err(e) => {
            let why = format!("{e:#}");
            return Ok(refused_page(&auth, StatusCode::BAD_REQUEST, &why));
        }
    };
    // Activating and replacing the whole policy end a hold; editing a part leaves it.
    let activate = matches!(op.as_str(), ACTIVATE | REPLACE);
    let changes = policy_changes(&current, &proposed);
    if changes.is_empty() && !(held && activate) {
        return Ok(super::clients::see_other(PATH));
    }
    let mut detail = Html::new();
    detail.raw("<ul>");
    if held && activate {
        detail.raw("<li>Activate the policy</li>");
    }
    for change in changes {
        detail.raw("<li>").text(change).raw("</li>");
    }
    // Before confirmation, warn of empty runner selections and lanes left without nodes.
    let edited = (op == SAVE)
        .then(|| field(&form, "lane").and_then(parse_lane))
        .flatten();
    if let Some(lane) = &edited
        && proposed.lane(lane).is_some_and(Lane::selects_nothing)
    {
        detail.raw(
            "<li class=\"bad\">This lane selects no pool or node: its runner gets no work \
                    until it does.</li>",
        );
    }
    // Warn for a runner lane with no matching node if it is new, previously had a node,
    // or is the edited lane with a changed selection. Empty edited selections are warned
    // above; confirmation answers need no repeated warnings.
    for lane in proposed.lanes.iter().filter(|_| !answer) {
        let Some(id) = lane.id().filter(|id| matches!(id, LaneId::Runner { .. })) else {
            continue;
        };
        let is_edited = edited.as_ref() == Some(&id);
        if is_edited && lane.selects_nothing() {
            continue;
        }
        let brought_about = current.lane(&id).is_none_or(|was| {
            !resolved(was, &known.nodes).is_empty() || (is_edited && was.pools != lane.pools)
        });
        if brought_about && resolved(lane, &known.nodes).is_empty() {
            detail
                .raw("<li class=\"bad\">No node can take the work of ")
                .text(known.label(&id))
                .raw(".</li>");
        }
    }
    detail.raw("</ul>");
    let ask = actions::Ask {
        path: PATH.to_owned(),
        back: PATH.to_owned(),
        op: op.clone(),
        what: "Change the capacity policy? Queued jobs it no longer allows wait, and \
               waiting requests may be refused.",
        detail,
        asked: vec![
            ("expected", expected.clone()),
            ("policy", serde_json::to_string(&proposed)?),
        ],
    };
    if let Some(response) =
        actions::ask_first(&site.questions, fleet::layout, htmx, &auth, &form, &ask)?
    {
        return Ok(response);
    }
    let (hub, actor) = (ui.hub.clone(), auth.session.principal());
    let result = blocking(move || {
        let now = crate::now_secs();
        Ok(if activate {
            hub.db
                .replace_capacity_policy_if(&proposed, &expected, &actor, now)
        } else {
            hub.db
                .edit_capacity_policy_if(&proposed, &expected, &actor, now)
        })
    })
    .await?;
    match result {
        Ok(true) => {
            ui.hub.touch();
            ui.hub.clients_changed();
        }
        Ok(false) => {}
        Err(e) => {
            let Some(refusal) = e.downcast_ref::<PolicyRefused>() else {
                return Err(e);
            };
            let (status, why) = match refusal {
                PolicyRefused::Conflict => (StatusCode::CONFLICT, STALE.to_owned()),
                PolicyRefused::Invalid(_) => (StatusCode::BAD_REQUEST, refusal.to_string()),
            };
            return Ok(refused_page(&auth, status, &why));
        }
    }
    Ok(super::clients::see_other(PATH))
}

fn refused_page(auth: &Auth, status: StatusCode, why: &str) -> Response<Body> {
    let mut main = Html::new();
    main.raw("<p class=\"message\">")
        .text(format!("Refused: {}.", why.trim_end_matches('.')))
        .raw("</p><p><a href=\"")
        .raw(PATH)
        .raw("\">Back</a></p>");
    let mut resp = page(fleet::layout("Lanes", PATH, auth, &main));
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_pages_lead_to_the_lanes() {
        for old in [
            OLD_PATH,
            OLDER_PATH,
            "/capacity/tenants/web",
            "/clients/tenants/web",
        ] {
            assert_eq!(moved(old).as_deref(), Some(PATH), "{old}");
        }
        assert_eq!(moved("/capacityx"), None);
    }

    #[test]
    fn lanes_are_named_in_queries_and_back() {
        for id in [
            LaneId::Runner {
                gitlab: "gl".into(),
                id: 42,
            },
            LaneId::Key("0123abcd".into()),
            LaneId::Default,
        ] {
            assert_eq!(parse_lane(&lane_param(&id)), Some(id));
        }
        for bad in ["runner/gl/0", "runner/gl", "key/", "other", "runner/../1"] {
            assert_eq!(parse_lane(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_lane_s_nodes_and_projects_are_named() {
        let node = "0123456789abcdef0123456789abcdef";
        let other = "fedcba9876543210fedcba9876543210";
        let known = Known {
            nodes: vec![
                KnownNode {
                    id: node.into(),
                    label: "n1".into(),
                    pools: Vec::new(),
                },
                KnownNode {
                    id: other.into(),
                    label: "n2".into(),
                    pools: vec!["trusted".into()],
                },
            ],
            ..Known::default()
        };
        let mut lane = Lane::new(&LaneId::Runner {
            gitlab: "gl".into(),
            id: 42,
        });
        assert_eq!(
            runs_on_parts(&lane, &known.nodes, MAX_LISTED_TARGETS).0,
            "no node"
        );
        assert_eq!(known.projects_text(&lane), "any");
        lane.pools = vec!["trusted".into()];
        assert_eq!(
            runs_on_parts(&lane, &known.nodes, MAX_LISTED_TARGETS).0,
            "n2"
        );
        lane.pools = vec![crate::policy::node_pool(node), "trusted".into()];
        assert_eq!(
            runs_on_parts(&lane, &known.nodes, MAX_LISTED_TARGETS).0,
            "n1, n2"
        );
        lane.pools = vec!["nowhere".into()];
        assert_eq!(
            runs_on_parts(&lane, &known.nodes, MAX_LISTED_TARGETS).0,
            "no node"
        );
        let key = Lane::new(&LaneId::Key("k".into()));
        assert_eq!(
            runs_on_parts(&key, &known.nodes, MAX_LISTED_TARGETS).0,
            "any node of the job's pool"
        );
        lane.projects = Some(vec![
            LaneProject {
                gitlab: "gl".into(),
                id: 7,
                branches: None,
            },
            LaneProject {
                gitlab: "gl".into(),
                id: 8,
                branches: Some(vec!["main".into(), "release/*".into()]),
            },
        ]);
        assert_eq!(known.projects_text(&lane), "7 · all; 8 · main, release/*");
        lane.projects = Some(vec![]);
        assert_eq!(known.projects_text(&lane), "none");
        assert_eq!(known.projects_text(&Lane::new(&LaneId::Default)), "-");
    }

    #[test]
    fn the_live_view_lists_waiting_lanes_by_held_for_weight() {
        use crate::jobs::{LastPick, LiveLane, Waiting};
        let runner = LaneId::Runner {
            gitlab: "gl".into(),
            id: 42,
        };
        let mut policy = Policy::default();
        policy.lanes.push(Lane {
            weight: 3,
            ..Lane::new(&runner)
        });
        let waiting = |job: Option<&str>, step, reason| Waiting {
            job: job.map(str::to_owned),
            relay: job.is_none().then(|| "r1".to_owned()),
            runner: job.is_none().then(|| "app-main".to_owned()),
            envelope: Envelope {
                mem_mib: 1024,
                cpus: 2,
                disk_bytes: 0,
            },
            step,
            waited_secs: 12,
            reason,
        };
        let mut shown = Shown {
            policy: Ok(policy.clone()),
            note: None,
            known: Known::default(),
            live: LiveView::default(),
        };
        shown.live.lanes.insert(
            runner.clone(),
            LiveLane {
                held: 6,
                waiting: vec![waiting(None, Step::Normal, "backoff")],
            },
        );
        shown.live.lanes.insert(
            LaneId::Default,
            LiveLane {
                held: 4,
                waiting: vec![waiting(Some("j1"), Step::Deadline, "lane at max slots")],
            },
        );
        shown.live.last_pick = Some(LastPick {
            lane: runner,
            step: Step::Normal,
            held: 5,
            weight: 3,
            at: 98,
        });
        let h = live_fragment(&shown, &policy, 100).into_string();
        for want in [
            "deadline <strong>1</strong>",
            "normal <strong>1</strong>",
            ": Runner 42, normal step, held ÷ weight 5 ÷ 3 = 1.7.",
            "<tr><td>Runner 42</td><td>6 ÷ 3 = 2.0</td><td><details data-keep=\"runner/gl/42\"><summary>1 waiting</summary>\
             <ul><li>request · relay r1 · app-main · normal · 1024 MiB",
            "· 12 s · backoff</li>",
            "<a href=\"/jobs/j1\">queued job</a> · deadline",
        ] {
            assert!(h.contains(want), "{want}: {h}");
        }
        // 2.0 before 4.0.
        assert!(
            h.find("Runner 42</td>") < h.find("Other API keys</td>"),
            "{h}"
        );
    }

    fn form(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        (pairs.iter())
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_runner_lane_is_set_from_its_form() {
        let id = LaneId::Runner {
            gitlab: "gl".into(),
            id: 42,
        };
        let mut before = Lane::new(&id);
        before.pools = vec!["b".into(), "a".into()];
        before.projects = Some(vec![
            LaneProject {
                gitlab: "gl".into(),
                id: 8,
                branches: None,
            },
            LaneProject {
                gitlab: "gl".into(),
                id: 7,
                branches: None,
            },
        ]);
        let lane = lane_from(
            &id,
            Some(&before),
            &form(&[
                ("class", "production"),
                ("weight", "3"),
                ("max_slots", ""),
                ("pools", "a"),
                ("pools", "b"),
                ("pools", " "),
                ("projects", "listed"),
                ("project", "7"),
                ("branches.7", "main\n release/*,x \n"),
                ("project", "8"),
                ("branches.8", "main"),
                ("project_new", "9"),
                ("branches.new", "main"),
            ]),
        )
        .unwrap();
        assert_eq!(lane.class, Class::Production);
        assert_eq!((lane.weight, lane.max_slots), (3, None));
        // The same targets in another order: kept as they were.
        assert_eq!(lane.pools, before.pools);
        let projects: Vec<_> = (lane.projects.iter().flatten())
            .map(|p| (p.id, p.branches.clone().unwrap_or_default().join("|")))
            .collect();
        assert_eq!(
            projects,
            [
                (8, "main".to_owned()),
                (7, "main|release/*,x".to_owned()),
                (9, "main".to_owned())
            ]
        );
        let lane = lane_from(
            &id,
            Some(&before),
            &form(&[
                ("class", "normal"),
                ("weight", "1"),
                ("max_slots", "4"),
                ("projects", "any"),
            ]),
        )
        .unwrap();
        assert_eq!(
            (lane.max_slots, lane.pools, lane.projects),
            (Some(4), Vec::new(), None)
        );
        let missing = form(&[("class", "normal"), ("weight", "1")]);
        assert!(lane_from(&id, None, &missing).is_err());
    }
}
