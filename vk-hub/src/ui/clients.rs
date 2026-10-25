//! `/clients`, Connections, for viewers and operators alike: on its GitLab tab the GitLab
//! servers, the relays and their runners; on its other tab the API keys the client API takes and
//! the client instances using each — the host, program and runners an instance's hello named,
//! when it was last heard from and what it holds. Both tabs' fragments are rendered once for all
//! open viewers' pages and once for all operators' ([`sse::feed`]), on what
//! [`Hub::clients_changed`] notes, and, while a page is open, once a heartbeat interval, which
//! moves the ages, what the instances hold and the relays' load.
//!
//! Operators create, revoke and remove keys here as `vk-hub keys create` and `vk-hub keys
//! revoke` do, as their session's principal. A key is created by a plain form outside the
//! fragment, whose answer is a page of its own showing the key this once: it is never in a
//! fragment, a log or the audit log. The operator's fragment carries a revoke button on each
//! working key, and a remove button on the newest of those that no longer work under a name no
//! working key holds, removing them all; as on `/operations`, it posts with the CSRF token the
//! page sets through `hx-headers`, and asks first ([`actions::ask_first`]). The store acts only
//! on the keys the operator confirmed ([`crate::store::Db::revoke_api_keys_as_seen`]).
//!
//! The GitLab tab shows the GitLab servers, then the relays enrolled — their reach, server,
//! what they report of it — and their runners, with what each is doing. Operators add GitLab
//! servers there, as `vk-hub gitlabs add` does, by a plain form outside the fragment, remove
//! one no relay is bound to, as `vk-hub gitlabs remove` does, and remove a relay, as `vk-hub
//! relays remove` does, by buttons in the fragment that ask first.
//!
//! Above them, *Pending* lists the GitLab servers relays report that no instance has, and the
//! projects whose jobs the approval gate refused, by instance; *Rejected* those an operator
//! rejected. Operators approve, reject and forget them there, as `vk-hub gitlabs
//! approve|reject|forget` and `vk-hub gitlabs projects approve|reject|forget` do: a server one
//! at a time, under the name its approval gives it, and an instance's projects together, by
//! ticking them. Each server's form and each project's box is `hx-preserve`d under an ID of
//! what it decides on, so the fragment's updates leave one being filled in alone.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::{self, csrf_field};
use super::sse;
use super::{Auth, Body, Ui, actions, blocking, field, page};
use crate::clients::{InstanceView, KeyView};
use crate::relays::RelayView;
use crate::server::Hub;
use crate::store::{
    ANY_POOL, CLIENT_ACTIVE_SECS, Decision, GitlabRefused, GitlabRow, KeyOp, KeyPolicy, KeyRefused,
    KeyRow, KeysChanged, PendingGitlab, ProjectRef, ProjectState, ProjectView, RejectedGitlab,
    Role,
};
use vk_hub_proto::gitlab::{RunnerState, ServerState, ServerStatus};

/// The page, and where its forms post.
pub(super) const PATH: &str = "/clients";

/// The event its fragment is swapped in on, and its stream's name under `/events/`.
pub(super) const EVENT: &str = "clients";

/// Key lifetimes the form offers, in days. The first is the default, matching
/// `vk-hub keys create`; the CLI takes any lifetime up to [`crate::store::MAX_KEY_TTL`].
const KEY_TTLS: [u64; 4] = [90, 7, 30, 365];

/// Where the key page suggests vk-gitlab keeps it.
const KEY_FILE: &str = "/etc/vk-gitlab/hub.key";

/// The other API clients' tab: the API keys and their instances.
pub(super) const OTHER: &str = "/clients?tab=other";

/// The event the GitLab tab's fragment is swapped in on, and its stream's name under
/// `/events/`. Both tabs' streams carry both tabs' fragments, rendered once for all of them.
pub(super) const GITLAB_EVENT: &str = "gitlab";

/// What the page shows: every key and its instances, the GitLab servers, those pending and
/// those rejected, every project decided or pending, and the relays.
struct Shown {
    views: Vec<KeyView>,
    gitlabs: Vec<(String, GitlabRow)>,
    pending: Vec<PendingGitlab>,
    rejected: Vec<(String, RejectedGitlab)>,
    projects: Vec<ProjectView>,
    relays: Vec<RelayView>,
}

impl Shown {
    /// Reads the database: call off the runtime.
    fn read(hub: &Hub) -> Result<Self> {
        Ok(Shown {
            views: crate::clients::views(hub)?,
            gitlabs: hub.db.gitlabs()?,
            pending: hub.db.pending_gitlabs()?,
            rejected: hub.db.rejected_gitlabs()?,
            projects: hub.db.gitlab_projects(None)?,
            relays: crate::relays::views(hub)?,
        })
    }
}

/// `GET /clients[?tab=other]`: Connections. Its GitLab tab, the default, lists the GitLab
/// servers the hub takes jobs from; its other tab is the API keys and their instances. Each
/// tab's fragment is live, on a stream of its own.
pub(super) async fn get(query: Option<&str>, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let form = super::decode_form(query.unwrap_or("").as_bytes());
    let other = field(&form, "tab") == Some("other");
    let hub = ui.hub.clone();
    let shown = blocking(move || Shown::read(&hub)).await?;
    let mut main = Html::new();
    main.raw("<h1>Connections</h1><nav class=\"tabs\" aria-label=\"Connection kinds\">")
        .raw("<a href=\"")
        .raw(PATH)
        .raw("\"")
        .raw(if other { "" } else { " aria-current=\"page\"" })
        .raw(">GitLab</a><a href=\"")
        .raw(OTHER)
        .raw("\"")
        .raw(if other { " aria-current=\"page\"" } else { "" })
        .raw(">Other API clients</a></nav>");
    let steer = auth.session.role >= Role::Operator;
    if steer {
        // The hub derives the hex token; htmx parses the header's JSON without evaluating it.
        main.raw("<div hx-headers=\"{&quot;X-CSRF-Token&quot;:&quot;")
            .text(&auth.csrf)
            .raw("&quot;}\"><div id=\"flash\"></div>");
    }
    let now = crate::now_secs();
    let (id, event, fragment) = if other {
        ("clients", EVENT, fragment(&shown.views, now, steer))
    } else {
        (
            "gitlab-servers",
            GITLAB_EVENT,
            gitlab_fragment(&shown, now, steer),
        )
    };
    main.raw("<div id=\"")
        .raw(id)
        .raw("\" hx-ext=\"sse\" sse-connect=\"/events/")
        .raw(event)
        .raw("\" sse-swap=\"")
        .raw(event)
        .raw("\" sse-close=\"close\">")
        .html(&fragment)
        .raw("</div>");
    if steer {
        main.raw("</div>");
        if other {
            create_form(&mut main, auth);
        } else {
            add_relay_form(&mut main, auth);
            add_server_form(&mut main, auth);
        }
    }
    Ok(page(fleet::layout("Connections", PATH, auth, &main)))
}

/// The GitLab tab: the GitLab servers the hub takes jobs from, then the relays and their
/// runners. With `steer`, a server no relay is bound to carries the button that removes it, and
/// each relay the one that removes it.
fn gitlab_fragment(shown: &Shown, now: u64, steer: bool) -> Html {
    let mut h = Html::new();
    pending_section(&mut h, shown, steer);
    h.raw("<section><h2>GitLab servers</h2>");
    if shown.gitlabs.is_empty() {
        if steer {
            h.raw("<p class=\"empty\">None yet: add one below or with <code>vk-hub gitlabs ")
                .raw("add &lt;name&gt; &lt;url&gt;</code>, or approve one a relay reports.</p>");
        } else {
            h.raw("<p class=\"empty\">None yet: <code>vk-hub gitlabs add &lt;name&gt; ")
                .raw("&lt;url&gt;</code> adds one, and <code>vk-hub gitlabs approve</code> one a ")
                .raw("relay reports.</p>");
        }
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>server</th><th>URL</th>")
            .raw("<th class=\"num\">relays</th><th class=\"num\">projects approved</th>");
        if steer {
            h.raw("<th>change</th>");
        }
        h.raw("</tr></thead><tbody>");
        for (name, row) in &shown.gitlabs {
            h.raw("<tr><td><strong>")
                .text(name)
                .raw("</strong></td><td>")
                .text(&row.url)
                .raw("</td><td class=\"num\">")
                .text(
                    (shown.relays.iter())
                        .filter(|r| r.row.server_url.as_deref() == Some(row.url.as_str()))
                        .count(),
                )
                .raw("</td><td class=\"num\">")
                .text(
                    (shown.projects.iter())
                        .filter(|p| p.gitlab == *name && p.row.state == ProjectState::Approved)
                        .count(),
                )
                .raw("</td>");
            if steer {
                h.raw("<td class=\"actions\">");
                if !bound(&shown.relays, &row.url) {
                    remove_server_button(&mut h, name);
                }
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section><section><h2>Relays</h2>");
    if shown.relays.is_empty() {
        h.raw(if steer {
            "<p class=\"empty\">None yet: add one below, or with <code>vk-hub token create \
             --kind gitlab</code> and <code>vk-gitlab join</code>.</p>"
        } else {
            "<p class=\"empty\">None yet: an operator enrolls a <code>vk-gitlab</code> with \
             <code>vk-hub token create --kind gitlab</code> and <code>vk-gitlab join</code>.</p>"
        });
    } else {
        relays_table(&mut h, &shown.relays, now, steer);
    }
    h.raw("</section><section><h2>Runners</h2>");
    runners_table(&mut h, &shown.relays, now);
    h.raw("</section>");
    h
}

/// *Pending*, then *Rejected* when an operator rejected any: the servers and the projects, each
/// with what an operator decides on — for an operator, the forms deciding.
fn pending_section(h: &mut Html, shown: &Shown, steer: bool) {
    let by_state = |state: ProjectState| {
        let mut groups: BTreeMap<&str, Vec<&ProjectView>> = BTreeMap::new();
        for p in shown.projects.iter().filter(|p| p.row.state == state) {
            groups.entry(&p.gitlab).or_default().push(p);
        }
        groups
    };
    let pending = by_state(ProjectState::Pending);
    h.raw("<section><h2>Pending</h2>");
    if shown.pending.is_empty() && pending.is_empty() {
        h.raw("<p class=\"empty\">Nothing waits for approval: a GitLab server a relay reports ")
            .raw("and a project a relay submits a job of wait here until an operator ")
            .raw("approves them.</p>");
    }
    if !shown.pending.is_empty() {
        h.raw("<h3>GitLab servers</h3>");
        if !steer {
            h.raw("<p class=\"sub\">An operator approves one under a name, as <code>vk-hub ")
                .raw("gitlabs approve &lt;url&gt; --name &lt;name&gt;</code> does, or rejects ")
                .raw("it. Check its certificate key first.</p>");
        }
        h.raw("<table class=\"grid\"><thead><tr><th>URL</th><th>certificate key sha256</th>")
            .raw("<th>reported by</th>");
        if steer {
            h.raw("<th>decide</th>");
        }
        h.raw("</tr></thead><tbody>");
        for p in &shown.pending {
            h.raw("<tr><td>").text(&p.url).raw("</td><td>");
            match &p.spki_sha256 {
                Some(spki) => h.raw("<code>").node(spki).raw("</code>"),
                None => h.raw("<span class=\"sub\">none reported</span>"),
            };
            if let Some(v) = &p.version {
                h.raw("<br><span class=\"sub\">GitLab ")
                    .node(v)
                    .raw("</span>");
            }
            h.raw("</td><td>");
            for (n, (_, hostname, since)) in p.relays.iter().enumerate() {
                if n > 0 {
                    h.raw("<br>");
                }
                h.node(hostname).raw(" since ");
                pages::at(h, *since);
            }
            h.raw("</td>");
            if steer {
                h.raw("<td class=\"actions\">");
                approve_server_form(h, &p.url);
                server_button(h, REJECT_SERVER, &p.url, "Reject");
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    for (gitlab, projects) in &pending {
        projects_form(h, shown, gitlab, projects, ProjectState::Pending, steer);
    }
    h.raw("</section>");
    let rejected = by_state(ProjectState::Rejected);
    if shown.rejected.is_empty() && rejected.is_empty() {
        return;
    }
    h.raw("<section><h2>Rejected</h2><p class=\"sub\">Their jobs are refused. Approving one ")
        .raw("takes the rejection back; forgetting one lets it wait for approval again at its ")
        .raw("next job.</p>");
    if !shown.rejected.is_empty() {
        h.raw("<h3>GitLab servers</h3><table class=\"grid\"><thead><tr><th>URL</th>")
            .raw("<th>rejected</th><th>by</th>");
        if steer {
            h.raw("<th>decide</th>");
        }
        h.raw("</tr></thead><tbody>");
        for (url, r) in &shown.rejected {
            h.raw("<tr><td>").text(url).raw("</td><td>");
            pages::at(h, r.rejected_at)
                .raw("</td><td>")
                .text(&r.rejected_by)
                .raw("</td>");
            if steer {
                h.raw("<td class=\"actions\">");
                approve_server_form(h, url);
                server_button(h, FORGET_SERVER, url, "Forget");
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    for (gitlab, projects) in &rejected {
        projects_form(h, shown, gitlab, projects, ProjectState::Rejected, steer);
    }
    h.raw("</section>");
}

/// The ops deciding on a server, and on an instance's projects.
const APPROVE_SERVER: &str = "approve-server";
const REJECT_SERVER: &str = "reject-server";
const FORGET_SERVER: &str = "forget-server";
const APPROVE_PROJECTS: &str = "approve-projects";
const REJECT_PROJECTS: &str = "reject-projects";
const FORGET_PROJECTS: &str = "forget-projects";

/// An ID for an element of `kind` showing `what`, from its digest: the same while it shows the
/// same, for `hx-preserve` to keep it as an operator fills it in.
fn preserved_id(kind: &str, what: &str) -> String {
    let digest = Sha256::digest(what.as_bytes());
    format!("{kind}-{}", vk_hub_proto::to_hex(&digest[..8]))
}

/// An operator's form approving the server at `url` under a name. No CSRF field: the page
/// around the fragment sets the token as a header.
fn approve_server_form(h: &mut Html, url: &str) {
    h.raw("<form id=\"")
        .text(preserved_id("approve", url))
        .raw("\" hx-preserve=\"true\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
        .raw(APPROVE_SERVER)
        .raw("\"><input type=\"hidden\" name=\"url\" value=\"")
        .text(url)
        .raw("\"><input type=\"text\" name=\"name\" aria-label=\"Name\" autocomplete=\"off\" ")
        .raw("spellcheck=\"false\" required size=\"10\" placeholder=\"name\">")
        .raw("<button class=\"primary\">Approve</button></form>");
}

/// A button posting `op` on the server at `url`.
fn server_button(h: &mut Html, op: &'static str, url: &str, label: &'static str) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
        .raw(op)
        .raw("\"><input type=\"hidden\" name=\"url\" value=\"")
        .text(url)
        .raw("\"><button class=\"danger\">")
        .raw(label)
        .raw("</button></form>");
}

/// The most projects of one instance and state listed, so that ticking them all still fits the
/// largest form a page posts.
const MAX_LISTED_PROJECTS: usize = 500;

/// Instance `gitlab`'s `projects` in `state`: each one's path and ID, its first job refused and
/// the relay that submitted it, since when and how many of its jobs were refused. For an
/// operator, a form ticking some of them to approve, reject (pending ones) or forget together.
fn projects_form(
    h: &mut Html,
    shown: &Shown,
    gitlab: &str,
    projects: &[&ProjectView],
    state: ProjectState,
    steer: bool,
) {
    let mut table = Html::new();
    table
        .raw("<table class=\"grid\"><thead><tr>")
        .raw(if steer { "<th></th>" } else { "" })
        .raw("<th>project</th><th class=\"num\">ID</th><th>first job refused</th>")
        .raw("<th>by relay</th><th>since</th><th class=\"num\">jobs refused</th>")
        .raw("</tr></thead><tbody>");
    for p in projects.iter().take(MAX_LISTED_PROJECTS) {
        table.raw("<tr>");
        if steer {
            table
                .raw("<td><input id=\"pick-")
                .raw(state.name())
                .raw("-")
                .text(gitlab)
                .raw("-")
                .text(p.id)
                .raw("\" hx-preserve=\"true\" type=\"checkbox\" name=\"project\" value=\"")
                .text(p.id)
                .raw("\" aria-label=\"")
                .text(p.id)
                .raw("\"></td>");
        }
        table.raw("<td>");
        if p.row.path.is_empty() {
            table.raw("<span class=\"sub\">path not known</span>");
        } else {
            table.node(&p.row.path);
        }
        table
            .raw("</td><td class=\"num\">")
            .text(p.id)
            .raw("</td><td>");
        match (p.row.first_job, &p.row.first_job_url) {
            (Some(job), url) => {
                table.external_link(url.as_deref(), &format!("#{job}"));
            }
            (None, _) => {
                table.raw("-");
            }
        }
        table.raw("</td><td>");
        match &p.row.relay {
            Some(id) => match shown.relays.iter().find(|r| r.id == *id) {
                Some(r) => table.node(&r.row.hostname),
                None => table
                    .raw("<code>")
                    .text(crate::rollout::short_id(id))
                    .raw("</code> <span class=\"sub\">removed</span>"),
            },
            None => table.raw("-"),
        };
        table.raw("</td><td>");
        pages::at(&mut table, p.row.since)
            .raw("</td><td class=\"num\">")
            .text(p.row.refused)
            .raw("</td></tr>");
    }
    table.raw("</tbody></table>");
    if let Some(more) = projects.len().checked_sub(MAX_LISTED_PROJECTS)
        && more > 0
    {
        table
            .raw("<p class=\"sub\">")
            .text(more)
            .raw(" more: <code>vk-hub gitlabs projects list ")
            .text(gitlab)
            .raw("</code> lists them all.</p>");
    }
    h.raw("<h3>Projects of <strong>")
        .text(gitlab)
        .raw("</strong></h3>");
    if !steer {
        h.html(&table);
        if state == ProjectState::Pending {
            h.raw("<p class=\"sub\">An operator approves them, as <code>vk-hub gitlabs ")
                .raw("projects approve ")
                .text(gitlab)
                .raw(" &lt;id&gt;…</code> does; a job then needs retrying in GitLab.</p>");
        }
        return;
    }
    // The instance as shown: one added since under its name is not the one decided on.
    let url = (shown.gitlabs.iter())
        .find(|(name, _)| name == gitlab)
        .map_or("", |(_, row)| row.url.as_str());
    let mut form = Html::new();
    form.raw("<input type=\"hidden\" name=\"gitlab\" value=\"")
        .text(gitlab)
        .raw("\"><input type=\"hidden\" name=\"url\" value=\"")
        .text(url)
        .raw("\"><fieldset><legend>Projects</legend>")
        .raw("<button type=\"button\" class=\"secondary\" data-check=\"all\">All</button>")
        .raw("<button type=\"button\" class=\"secondary\" data-check=\"none\">None</button>")
        .html(&table)
        .raw("</fieldset><button class=\"primary\" name=\"op\" value=\"")
        .raw(APPROVE_PROJECTS)
        .raw("\">Approve</button>");
    if state == ProjectState::Pending {
        form.raw("<button class=\"danger\" name=\"op\" value=\"")
            .raw(REJECT_PROJECTS)
            .raw("\">Reject</button>");
    }
    form.raw("<button class=\"secondary\" name=\"op\" value=\"")
        .raw(FORGET_PROJECTS)
        .raw("\">Forget</button>");
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\">")
        .html(&form)
        .raw("</form>");
}

/// Whether one of `relays` is bound to the GitLab server at `url`: while one is, the store
/// refuses to remove the server.
fn bound(relays: &[RelayView], url: &str) -> bool {
    relays
        .iter()
        .any(|r| r.row.server_url.as_deref() == Some(url))
}

/// Each relay: its reach, the GitLab server it is bound to and what the hub makes of it, what it
/// reports of that server, its version and runners. With `steer`, the button removing it.
fn relays_table(h: &mut Html, relays: &[RelayView], now: u64, steer: bool) {
    h.raw("<table class=\"grid\"><thead><tr><th>relay</th><th>state</th><th>last heard</th>")
        .raw("<th>server</th><th>GitLab</th><th>version</th><th class=\"num\">runners</th>")
        .raw("<th class=\"num\">concurrent</th>");
    if steer {
        h.raw("<th>change</th>");
    }
    h.raw("</tr></thead><tbody>");
    for r in relays {
        let inventory = r.row.inventory.as_ref();
        h.raw("<tr><td><strong>")
            .node(&r.row.hostname)
            .raw("</strong> <code class=\"sub\">")
            .text(crate::rollout::short_id(&r.id))
            .raw("</code></td><td>")
            .raw(if r.connected {
                "<span class=\"badge ok\">connected</span>"
            } else {
                "<span class=\"badge bad\">unreachable</span>"
            })
            .raw("</td><td>");
        match r.row.last_seen {
            Some(t) => super::fleet::time_ago(h, now, t),
            None => h.raw("never"),
        };
        h.raw("</td><td>");
        match &r.server {
            Some(status) => server_status(h, status),
            None => {
                h.raw("<span class=\"sub\">not reported yet</span>");
            }
        }
        h.raw("</td><td>");
        match inventory {
            Some(i) => {
                h.external_link(Some(&i.server.url), &i.server.url);
                if let Some(spki) = &i.server.spki_sha256 {
                    h.raw("<br><span class=\"sub\">certificate key sha256 <code>")
                        .node(spki)
                        .raw("</code></span>");
                }
                if let Some(v) = &i.server.version {
                    h.raw("<br><span class=\"sub\">GitLab ")
                        .node(v)
                        .raw("</span>");
                }
            }
            None => {
                h.raw("-");
            }
        }
        h.raw("</td><td>")
            .node(inventory.map_or("-", |i| i.version.as_str()))
            .raw("</td><td class=\"num\">")
            .text(inventory.map_or(0, |i| i.runners.len()))
            .raw("</td><td class=\"num\">")
            .text(inventory.map_or(0, |i| i.concurrent))
            .raw("</td>");
        if steer {
            h.raw("<td class=\"actions\"><form method=\"post\" action=\"")
                .raw(PATH)
                .raw("\" hx-post=\"")
                .raw(PATH)
                .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
                .raw(REMOVE_RELAY)
                .raw("\"><input type=\"hidden\" name=\"relay\" value=\"")
                .text(&r.id)
                .raw("\"><button class=\"danger\">Remove</button></form></td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// What the hub makes of a relay's server: its name once approved, else its URL and why not.
fn server_status(h: &mut Html, s: &ServerStatus) {
    match (s.state, &s.name) {
        (ServerState::Approved, Some(name)) => {
            h.raw("<strong>").text(name).raw("</strong>");
        }
        (state, _) => {
            h.text(&s.url).raw(" ").raw(match state {
                ServerState::Approved => "<span class=\"badge ok\">approved</span>",
                ServerState::Pending => "<span class=\"badge warn\">pending</span>",
                ServerState::Rejected => "<span class=\"badge bad\">rejected</span>",
                ServerState::Rebound => {
                    "<span class=\"badge bad\">reports another server: enroll it again</span>"
                }
                ServerState::Other => "<span class=\"badge\">unknown</span>",
            });
        }
    }
}

/// Each relay's runners: GitLab's ID for each, where its jobs go, how many at once, whether
/// GitLab took its token, what it is doing and its load, as the relay last said.
fn runners_table(h: &mut Html, relays: &[RelayView], now: u64) {
    let runners = || {
        relays.iter().flat_map(|r| {
            (r.row.inventory.iter())
                .flat_map(|i| &i.runners)
                .map(move |runner| (r, runner))
        })
    };
    if runners().next().is_none() {
        h.raw("<p class=\"empty\">none: no relay has reported a runner yet</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>relay</th><th>runner</th>")
        .raw("<th>GitLab ID</th><th>placement</th><th class=\"num\">limit</th><th>state</th>")
        .raw("<th class=\"num\">requests</th><th class=\"num\">jobs</th>")
        .raw("<th>last GitLab answer</th></tr></thead><tbody>");
    for (r, runner) in runners() {
        let report = (r.row.report.iter())
            .flat_map(|rep| &rep.runners)
            .find(|rep| rep.name == runner.name);
        let load = (r.row.heartbeat.iter())
            .flat_map(|hb| &hb.runners)
            .find(|l| l.name == runner.name);
        let p = &runner.placement;
        h.raw("<tr><td>")
            .node(&r.row.hostname)
            .raw("</td><td>")
            .node(&runner.name)
            .raw("</td><td>");
        match runner.runner_id {
            Some(id) => h.text(id),
            None => h.raw("-"),
        };
        h.raw("</td><td>pool ").node(&p.pool);
        if !p.labels.is_empty() {
            h.raw(" · ").node(&p.labels.join(", "));
        }
        h.raw(" · ")
            .text(crate::store::envelope_text(p.envelope))
            .raw("</td><td class=\"num\">");
        match runner.limit {
            Some(n) => h.text(n),
            None => h.raw("-"),
        };
        h.raw("</td><td>");
        if !runner.verified {
            h.raw("<span class=\"badge bad\">token not verified</span> ");
        }
        match report {
            Some(rep) => {
                h.raw(runner_badge(rep.state));
                if let Some(m) = &rep.message {
                    h.raw(" <span class=\"sub\">").node(m).raw("</span>");
                }
            }
            None => {
                h.raw("-");
            }
        }
        h.raw("</td>");
        match load {
            Some(l) => {
                h.raw("<td class=\"num\">")
                    .text(l.requests)
                    .raw("</td><td class=\"num\">")
                    .text(l.jobs)
                    .raw("</td><td>");
                if let Some(t) = l.last_answer_at {
                    super::fleet::time_ago(h, now, t);
                    if let Some(status) = l.last_status {
                        h.raw(" · HTTP ").text(status);
                    }
                } else {
                    h.raw("-");
                }
                h.raw("</td>");
            }
            None => {
                h.raw("<td class=\"num\">-</td><td class=\"num\">-</td><td>-</td>");
            }
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// A runner's state as a badge.
fn runner_badge(state: RunnerState) -> &'static str {
    match state {
        RunnerState::Polling => "<span class=\"badge ok\">polling</span>",
        RunnerState::WaitingCapacity => "<span class=\"badge busy\">waiting for capacity</span>",
        RunnerState::ServerPending => "<span class=\"badge warn\">server not approved</span>",
        RunnerState::Unhealthy => "<span class=\"badge bad\">unhealthy</span>",
        RunnerState::TokenRefused => "<span class=\"badge bad\">token refused</span>",
        RunnerState::Other => "<span class=\"badge\">unknown</span>",
    }
}

/// The op removing a relay.
const REMOVE_RELAY: &str = "remove-relay";

/// A button posting the removal of the GitLab server named `name`: `remove` of a `server`, not
/// of a key's `name`. No CSRF field: the page around the fragment sets the token as a header.
fn remove_server_button(h: &mut Html, name: &str) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"remove\">")
        .raw("<input type=\"hidden\" name=\"server\" value=\"")
        .text(name)
        .raw("\"><button class=\"danger\">Remove</button></form>");
}

/// An operator's form issuing a relay's enrollment token, outside the live fragment: a plain
/// POST answered by a page of its own showing the token, as for a node's.
fn add_relay_form(h: &mut Html, auth: &Auth) {
    h.raw("<section><h2>Add a relay</h2><form method=\"post\" action=\"")
        .raw(fleet::TOKEN_PATH)
        .raw("\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"kind\" value=\"gitlab\">")
        .raw("<input type=\"hidden\" name=\"ttl\" value=\"3600\">")
        .raw("<button class=\"primary\">Issue a relay token, valid an hour</button></form>")
        .raw("<p class=\"sub\">Single-use: a <code>vk-gitlab</code> redeems it with ")
        .raw("<code>vk-gitlab join</code>, as <code>vk-hub token create --kind gitlab</code> ")
        .raw("issues one. Shown a single time.</p></section>");
}

/// The op adding a GitLab server.
const ADD_SERVER: &str = "add-server";

/// An operator's form adding a GitLab server, outside the live fragment: a plain POST.
fn add_server_form(h: &mut Html, auth: &Auth) {
    h.raw("<section><h2>Add a GitLab server</h2><form class=\"wide\" method=\"post\" ")
        .raw("action=\"")
        .raw(PATH)
        .raw("\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .raw(ADD_SERVER)
        .raw("\"><label for=\"gitlab-name\">Name</label>")
        .raw("<input id=\"gitlab-name\" type=\"text\" name=\"name\" autocomplete=\"off\" ")
        .raw("spellcheck=\"false\" required placeholder=\"gl\">")
        .raw("<label for=\"gitlab-url\">URL</label>")
        .raw("<input id=\"gitlab-url\" type=\"url\" name=\"url\" autocomplete=\"off\" ")
        .raw("spellcheck=\"false\" required placeholder=\"https://gitlab.example.com\">")
        .raw("<button class=\"primary\">Add</button></form>")
        .raw("<p class=\"sub\">As <code>vk-hub gitlabs add</code>, it approves the server ")
        .raw("before a relay reports it: the name is what registry namespaces and egress rules ")
        .raw("call the server, lowercase letters, digits and <code>-</code>; the URL is the one ")
        .raw("its relays' <code>[gitlab] url</code> names.</p></section>");
}

/// The fragments, as one rendering for every page showing them: with the keys' buttons for an
/// operator's, without for a viewer's. The other tab's first, then the GitLab tab's.
pub(super) fn events(hub: &Arc<Hub>, steer: bool) -> sse::Events {
    let other: sse::Render = {
        let hub = hub.clone();
        Arc::new(move || {
            let views = crate::clients::views(&hub)?;
            Ok(fragment(&views, crate::now_secs(), steer).into_string())
        })
    };
    let gitlab: sse::Render = {
        let hub = hub.clone();
        Arc::new(move || {
            let shown = Shown::read(&hub)?;
            Ok(gitlab_fragment(&shown, crate::now_secs(), steer).into_string())
        })
    };
    sse::Events::from([(EVENT, other), (GITLAB_EVENT, gitlab)])
}

/// The other tab: the keys, then their instances.
fn fragment(views: &[KeyView], now: u64, steer: bool) -> Html {
    let keys: Vec<&KeyView> = views.iter().collect();
    let mut h = Html::new();
    h.raw("<section><h2>API keys</h2>");
    if keys.is_empty() {
        h.raw(if steer {
            "<p class=\"empty\">none: create one below or with <code>vk-hub keys create</code>"
        } else {
            "<p class=\"empty\">none: <code>vk-hub keys create</code> creates one"
        });
        h.raw("</p>");
    } else {
        keys_table(&mut h, &keys, views, now, steer);
    }
    h.raw("</section><section><h2>Instances</h2>");
    instances_table(
        &mut h,
        &keys,
        views,
        now,
        "none: no client has used a key yet",
    );
    h.raw("</section>");
    h
}

/// The keys `rows` of all the keys `views`. With `steer`, a working key carries the button that
/// revokes it; under a name [`target`] would remove keys of, the newest carries the button that
/// removes them all.
fn keys_table(h: &mut Html, rows: &[&KeyView], views: &[KeyView], now: u64, steer: bool) {
    let working: HashSet<&str> = views
        .iter()
        .filter(|v| v.row.live(now))
        .map(|v| v.row.name.as_str())
        .collect();
    let mut removable: HashMap<&str, &KeyView> = HashMap::new();
    for v in views
        .iter()
        .filter(|v| !working.contains(v.row.name.as_str()))
    {
        let newest = removable.entry(&v.row.name).or_insert(v);
        if v.row.created_at >= newest.row.created_at {
            *newest = v;
        }
    }
    h.raw("<table class=\"grid\"><thead><tr>")
        .raw("<th>name</th><th>key</th><th>scopes</th><th>pools</th><th>largest</th>")
        .raw("<th>created</th><th>by</th><th>state</th><th>last heard</th>")
        .raw("<th class=\"num\">instances</th><th class=\"num\">jobs</th>");
    if steer {
        h.raw("<th>change</th>");
    }
    h.raw("</tr></thead><tbody>");
    for &v in rows {
        key_row(h, v, views, now);
        if steer {
            h.raw("<td class=\"actions\">");
            if v.row.live(now) {
                change_button(h, KeyOp::Revoke, "Revoke", &v.row.name);
            } else if removable
                .get(v.row.name.as_str())
                .is_some_and(|newest| std::ptr::eq(*newest, v))
            {
                change_button(h, KeyOp::Remove, "Remove", &v.row.name);
            }
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// The instances shown of the keys `rows` of all the keys `views`; `empty` when there are none.
fn instances_table(h: &mut Html, rows: &[&KeyView], views: &[KeyView], now: u64, empty: &str) {
    if rows.iter().all(|v| shown(views, v, now).next().is_none()) {
        h.raw("<p class=\"empty\">").text(empty).raw("</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr>")
        .raw("<th>key</th><th>host</th><th>instance</th><th>program</th><th>runners</th>")
        .raw("<th>last heard</th><th class=\"num\">reservations</th>")
        .raw("<th class=\"num\">queued</th><th class=\"num\">running</th></tr></thead><tbody>");
    for v in rows {
        for i in shown(views, v, now) {
            instance_row(h, &v.row, i, now);
        }
    }
    h.raw("</tbody></table>");
}

/// Whether instance `i` of key `v` is one a working key shows too, while `v` no longer works and `i` holds nothing: the same client, now using
/// another key, which would otherwise show twice.
fn superseded(views: &[KeyView], v: &KeyView, i: &InstanceView, now: u64) -> bool {
    let w = i.work;
    !v.row.live(now)
        && !i.row.instance.is_empty()
        && (w.reservations, w.queued, w.running) == (0, 0, 0)
        && views.iter().any(|o| {
            o.row.live(now) && o.instances.iter().any(|j| j.row.instance == i.row.instance)
        })
}

/// The instances of key `v` to show: those not [`superseded`].
fn shown<'a>(
    views: &'a [KeyView],
    v: &'a KeyView,
    now: u64,
) -> impl Iterator<Item = &'a InstanceView> {
    (v.instances.iter()).filter(move |i| !superseded(views, v, i, now))
}

/// Key `v`'s row, left open for an operator's button; `views` all the keys, to count only the
/// instances shown ([`superseded`]).
fn key_row(h: &mut Html, v: &KeyView, views: &[KeyView], now: u64) {
    let k = &v.row;
    let scopes: Vec<&str> = k.scopes.iter().map(|s| s.name()).collect();
    let pools: Vec<&str> = (k.pools.iter())
        .map(|p| if p == ANY_POOL { "any" } else { p })
        .collect();
    h.raw("<tr><td>")
        .text(&k.name)
        .raw("</td><td><code>vkk_")
        .text(&k.prefix)
        .raw("…</code></td><td>")
        .text(scopes.join(", "))
        .raw("</td><td>")
        .text(pools.join(", "))
        .raw("</td><td>")
        .text(
            k.max_envelope
                .map_or_else(pages::dash, crate::store::envelope_text),
        )
        .raw("</td><td>");
    pages::at(h, k.created_at)
        .raw("</td><td>")
        .text(&k.created_by)
        .raw("</td><td>");
    if k.revoked_at.is_some() {
        h.raw("<span class=\"badge bad\">revoked</span>");
    } else if k.expires_at <= now {
        h.raw("<span class=\"badge warn\">expired</span>");
    } else {
        h.raw("expires ");
        pages::at(h, k.expires_at);
    }
    h.raw("</td><td>");
    match v.last_seen() {
        Some(t) => heard_at(h, now, t, k.live(now)),
        None => {
            h.raw("-");
        }
    }
    h.raw("</td><td class=\"num\">")
        .text(shown(views, v, now).count())
        .raw("</td><td class=\"num\">");
    // The jobs page takes only a SHA-256 for a key: what the hub stores a key under.
    if vk_hub_proto::valid_sha256(&v.id) {
        h.raw("<a href=\"")
            .raw(super::jobs::PATH)
            .raw("?key=")
            .text(&v.id)
            .raw("\">")
            .text(v.jobs)
            .raw("</a>");
    } else {
        h.text(v.jobs);
    }
    h.raw("</td>");
}

/// A button posting `op` on the key named `name`. No CSRF field: the page around the fragment
/// sets the token as a header.
fn change_button(h: &mut Html, op: KeyOp, label: &'static str, name: &str) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
        .raw(op.name())
        .raw("\"><input type=\"hidden\" name=\"name\" value=\"")
        .text(name)
        .raw("\"><button class=\"danger\">")
        .raw(label)
        .raw("</button></form>");
}

/// An operator's form creating a key, outside the live fragment: a plain POST, answered by a
/// page of its own showing the key, so it is never sent in a fragment shared by every page.
fn create_form(h: &mut Html, auth: &Auth) {
    h.raw("<section><h2>Create an API key</h2><form class=\"wide\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"create\">")
        .raw("<label for=\"key-name\">Name</label>")
        .raw("<input id=\"key-name\" type=\"text\" name=\"name\" autocomplete=\"off\" ")
        .raw("spellcheck=\"false\" required placeholder=\"gitlab-ci\">")
        .raw("<label for=\"key-pools\">Pools</label>")
        .raw("<input id=\"key-pools\" type=\"text\" name=\"pools\" autocomplete=\"off\" ")
        .raw("spellcheck=\"false\" required placeholder=\"ci, build or *\">")
        .raw("<fieldset><legend>Scopes</legend><label><input type=\"checkbox\" name=\"scope\" ")
        .raw("value=\"jobs\" checked> jobs</label><label><input type=\"checkbox\" ")
        .raw("name=\"scope\" value=\"capacity\"> capacity</label></fieldset>")
        .raw("<label for=\"key-mem\">Largest memory</label>")
        .raw("<input id=\"key-mem\" type=\"text\" name=\"max_mem\" autocomplete=\"off\" ")
        .raw("placeholder=\"any, or 16G\">")
        .raw("<label for=\"key-cpus\">Largest CPUs</label>")
        .raw("<input id=\"key-cpus\" type=\"text\" inputmode=\"numeric\" name=\"max_cpus\" ")
        .raw("autocomplete=\"off\" placeholder=\"any, or 8\">")
        .raw("<label for=\"key-disk\">Largest disk</label>")
        .raw("<input id=\"key-disk\" type=\"text\" name=\"max_disk\" autocomplete=\"off\" ")
        .raw("placeholder=\"any, or 64G\">")
        .raw("<label for=\"key-ttl\">Valid for</label><select id=\"key-ttl\" name=\"ttl\">");
    for days in KEY_TTLS {
        h.raw("<option value=\"")
            .text(days)
            .raw("\">")
            .text(days)
            .raw(" days</option>");
    }
    h.raw("</select><button class=\"primary\">Create</button></form>")
        .raw("<p class=\"sub\">As <code>vk-hub keys create</code>: scope <code>jobs</code> is ")
        .raw("the client API but job submission, which takes an enrolled relay; ")
        .raw("<code>capacity</code> only asks for room. Pools are ")
        .raw("comma-separated, <code>*</code> for any. A job's largest memory and disk take ")
        .raw("<code>&lt;n&gt;K|M|G|T</code>; memory at least <code>1M</code>. A limit left ")
        .raw("empty is unbounded. The key is shown a single time.</p></section>");
}

/// `POST /clients`: create (`create`), revoke (`revoke`) or remove (`remove`) a key, or add
/// (`add-server`) or remove (`remove` with a `server`) a GitLab server, as the operator session's
/// principal, as `vk-hub keys create|revoke` and `vk-hub gitlabs add|remove` do.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    match field(&form, "op") {
        Some("create") => create(ui, &auth, &form).await,
        Some("revoke") => revoke(ui, site, htmx, &auth, &form, KeyOp::Revoke).await,
        Some("remove") if field(&form, "server").is_some() => {
            remove_server(ui, site, htmx, &auth, &form).await
        }
        Some("remove") => revoke(ui, site, htmx, &auth, &form, KeyOp::Remove).await,
        Some(ADD_SERVER) => add_server(ui, &auth, &form).await,
        Some(REMOVE_RELAY) => remove_relay(ui, site, htmx, &auth, &form).await,
        Some(op @ (APPROVE_SERVER | REJECT_SERVER | FORGET_SERVER)) => {
            decide_server(ui, htmx, &auth, &form, op).await
        }
        Some(op @ (APPROVE_PROJECTS | REJECT_PROJECTS | FORGET_PROJECTS)) => {
            decide_projects(ui, htmx, &auth, &form, op).await
        }
        _ => Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "No such action.",
        )),
    }
}

/// Create the key `form` asks for, and show it this once with the vk-gitlab config using it.
/// Its policy is checked as the CLI's: by [`crate::store::Db::create_api_key`], which refuses
/// a bad name, pool or lifetime, and its limits parsed as the CLI parses them.
async fn create(ui: &Ui, auth: &Auth, form: &[(String, String)]) -> Result<Response<Body>> {
    let refused = |why: String| refused_page(auth, "API key", OTHER, &why);
    let mut scopes = Vec::new();
    for (_, s) in form.iter().filter(|(k, _)| k == "scope") {
        match crate::parse_scope(s) {
            Ok(scope) => scopes.push(scope),
            Err(why) => return Ok(refused(why)),
        }
    }
    let pools: Vec<String> = field(form, "pools")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    let limit = |name: &str| field(form, name).map(str::trim).filter(|v| !v.is_empty());
    let max_mem = match limit("max_mem").map(crate::parse_mem_size).transpose() {
        Ok(v) => v,
        Err(why) => return Ok(refused(format!("largest memory {why}"))),
    };
    let max_cpus = match limit("max_cpus").map(str::parse::<u32>).transpose() {
        Ok(v) => v,
        Err(_) => return Ok(refused("largest CPUs: expected a whole number".into())),
    };
    let max_disk = match limit("max_disk").map(crate::parse_size).transpose() {
        Ok(v) => v,
        Err(why) => return Ok(refused(format!("largest disk {why}"))),
    };
    let Some(days) = field(form, "ttl")
        .and_then(|t| t.parse::<u64>().ok())
        .filter(|d| KEY_TTLS.contains(d))
    else {
        return Ok(refused("not one of the form's lifetimes".into()));
    };
    let policy = KeyPolicy::with_limits(scopes, pools, max_mem, max_cpus, max_disk);
    let name = field(form, "name").unwrap_or("").to_string();
    let ttl = Duration::from_secs(days.saturating_mul(86_400));
    let (hub, principal, named) = (ui.hub.clone(), auth.session.principal(), name.clone());
    let created = blocking(move || {
        Ok(hub
            .db
            .create_api_key(&named, &policy, ttl, &principal, crate::now_secs()))
    })
    .await?;
    let (key, row) = match created {
        Ok(created) => created,
        Err(e) if e.is::<KeyRefused>() => return Ok(refused(e.to_string())),
        Err(e) => return Err(e),
    };
    ui.hub.clients_changed();
    // The key itself is never logged: it is the credential.
    eprintln!(
        "vk-hub: ui: {} created API key {name}",
        auth.session.principal()
    );
    let mut main = Html::new();
    main.raw("<h1>API key</h1><p>Key <strong>")
        .text(&row.name)
        .raw("</strong> works until ");
    pages::at(&mut main, row.expires_at)
        .raw(". It is shown this once: copy it now.</p><pre>")
        .text(&key)
        .raw("</pre><p>Keep it in a file only vk-gitlab's user reads, such as <code>")
        .raw(KEY_FILE)
        .raw("</code>, and point vk-gitlab's config at it:</p><pre>[hub]\nurl = \"");
    match &ui.hub.node_url {
        Some(url) => main.text(url),
        None => main.raw("&lt;hub-url&gt;"),
    };
    main.raw("\"\napi_key_file = \"")
        .raw(KEY_FILE)
        .raw("\"</pre><p class=\"sub\">Add <code>ca_file</code> when the hub's certificate ")
        .raw("is not one the system's roots verify.</p><p><a href=\"")
        .raw(OTHER)
        .raw("\">Back to the API clients</a></p>");
    Ok(page(fleet::layout("API key", PATH, auth, &main)))
}

/// A plain form's refusal, `why`, as a page titled `title` leading back to `back`.
fn refused_page(auth: &Auth, title: &str, back: &'static str, why: &str) -> Response<Body> {
    let mut main = Html::new();
    main.raw("<p class=\"message\">")
        .text(format!("Refused: {why}."))
        .raw("</p><p><a href=\"")
        .raw(back)
        .raw("\">")
        .raw(if back == OTHER {
            "Back to the API clients"
        } else {
            "Back to the GitLab servers"
        })
        .raw("</a></p>");
    let mut resp = page(fleet::layout(title, PATH, auth, &main));
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    resp
}

/// Add the GitLab server `form` names, checked and audited by
/// [`crate::store::Db::add_gitlab`] as for `vk-hub gitlabs add`, then back to the GitLab tab.
/// The relays bound to it are told it is approved.
async fn add_server(ui: &Ui, auth: &Auth, form: &[(String, String)]) -> Result<Response<Body>> {
    let name = field(form, "name").unwrap_or("").trim().to_string();
    let url = field(form, "url").unwrap_or("").to_string();
    let (hub, principal, named) = (ui.hub.clone(), auth.session.principal(), name.clone());
    let added = blocking(move || {
        let added = hub
            .db
            .add_gitlab(&named, &url, &principal, crate::now_secs());
        if let Ok(row) = &added {
            crate::relays::server_changed(&hub, &row.url)?;
        }
        Ok(added)
    })
    .await?;
    let row = match added {
        Ok(row) => row,
        Err(e) if e.is::<GitlabRefused>() => {
            return Ok(refused_page(auth, "GitLab server", PATH, &e.to_string()));
        }
        Err(e) => return Err(e),
    };
    ui.hub.clients_changed();
    eprintln!(
        "vk-hub: ui: {} added GitLab instance {name} at {}",
        auth.session.principal(),
        row.url
    );
    Ok(see_other(PATH))
}

/// Remove the GitLab server `form` names (`server`) once confirmed, as `vk-hub gitlabs remove`
/// does. The question names the server as it was added, and the store removes it only if it
/// still is, so a namesake added since is left alone; it refuses while a relay is bound to it
/// ([`crate::store::Db::remove_gitlab_as_seen`]).
async fn remove_server(
    ui: &Ui,
    site: &FleetSite,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
) -> Result<Response<Body>> {
    let name = field(form, "server").unwrap_or("").to_string();
    let (hub, named) = (ui.hub.clone(), name.clone());
    let row = blocking(move || hub.db.gitlab(&named)).await?;
    let Some(row) = row else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such GitLab server.",
        ));
    };
    let mut detail = Html::new();
    detail
        .raw("<p><strong>")
        .text(&name)
        .raw("</strong>: ")
        .text(&row.url)
        .raw(", added by ")
        .text(&row.created_by)
        .raw("</p>");
    let ask = actions::Ask {
        path: PATH.to_string(),
        back: PATH.to_string(),
        op: "remove".to_string(),
        what: "Remove this GitLab server? Its projects' approvals go with it, and a relay that \
               reports it again waits for approval; its name stays taken until its jobs leave \
               the history.",
        detail,
        asked: vec![
            ("server", name.clone()),
            ("added", format!("{} {}", row.created_at, row.url)),
        ],
    };
    if let Some(asked) = actions::ask_first(&site.questions, fleet::layout, htmx, auth, form, &ask)?
    {
        return Ok(asked);
    }
    let (hub, principal, named) = (ui.hub.clone(), auth.session.principal(), name.clone());
    let done = blocking(move || {
        Ok(hub
            .db
            .remove_gitlab_as_seen(&named, &row, &principal, crate::now_secs()))
    })
    .await?;
    match done {
        Ok(true) => {}
        Ok(false) => {
            return Ok(actions::refused(
                htmx,
                StatusCode::NOT_FOUND,
                "There is no such GitLab server.",
            ));
        }
        Err(e) if e.is::<GitlabRefused>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {e}."),
            ));
        }
        Err(e) => return Err(e),
    }
    ui.hub.clients_changed();
    eprintln!(
        "vk-hub: ui: {} removed GitLab instance {name}",
        auth.session.principal()
    );
    if !htmx {
        return Ok(see_other(PATH));
    }
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">")
        .text(format!("Removed GitLab server {name}."))
        .raw("</div>");
    Ok(actions::swap_none(super::html_response(StatusCode::OK, h)))
}

/// Remove the relay `form` names (`relay`) once confirmed, as `vk-hub relays remove` does: its
/// key is no longer pinned and its session ends ([`crate::relays::remove`]).
async fn remove_relay(
    ui: &Ui,
    site: &FleetSite,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
) -> Result<Response<Body>> {
    let id = field(form, "relay").unwrap_or("").to_string();
    let (hub, wanted) = (ui.hub.clone(), id.clone());
    let relay = if vk_hub_proto::valid_id(&id) {
        blocking(move || crate::relays::detail(&hub, &wanted)).await?
    } else {
        None
    };
    let Some(relay) = relay else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such relay.",
        ));
    };
    let mut detail = Html::new();
    detail
        .raw("<p><strong>")
        .node(&relay.row.hostname)
        .raw("</strong> <code>")
        .text(&relay.id)
        .raw("</code>");
    if let Some(s) = &relay.server {
        detail.raw(", GitLab ").text(crate::relays::server_text(s));
    }
    detail.raw("</p>");
    let ask = actions::Ask {
        path: PATH.to_string(),
        back: PATH.to_string(),
        op: REMOVE_RELAY.to_string(),
        what: "Remove this relay? Its key is no longer trusted and its session ends: it takes \
               no more jobs, and can no longer follow or settle those under way. Enrolling it \
               again takes a new token and `vk-gitlab join --replace`.",
        detail,
        asked: vec![("relay", id.clone())],
    };
    if let Some(asked) = actions::ask_first(&site.questions, fleet::layout, htmx, auth, form, &ask)?
    {
        return Ok(asked);
    }
    let (hub, principal, wanted) = (ui.hub.clone(), auth.session.principal(), id.clone());
    let removed = blocking(move || crate::relays::remove(&hub, &principal, &wanted)).await?;
    if !removed {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such relay.",
        ));
    }
    eprintln!(
        "vk-hub: ui: {} removed relay {id}",
        auth.session.principal()
    );
    if !htmx {
        return Ok(see_other(PATH));
    }
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">Removed relay ")
        .node(&relay.row.hostname)
        .raw(".</div>");
    Ok(actions::swap_none(super::html_response(StatusCode::OK, h)))
}

/// Approve the server at the `url` `form` names under its `name`, as `vk-hub gitlabs approve`
/// does, or reject it or forget its rejection, as `vk-hub gitlabs reject|forget` do; its relays
/// are told. Refusals, such as a name taken, are shown as the store gives them.
async fn decide_server(
    ui: &Ui,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    op: &str,
) -> Result<Response<Body>> {
    let url = field(form, "url").unwrap_or("").to_string();
    let name = field(form, "name").unwrap_or("").trim().to_string();
    let (hub, principal, op_, named) = (
        ui.hub.clone(),
        auth.session.principal(),
        op.to_string(),
        name.clone(),
    );
    let done = blocking(move || {
        let now = crate::now_secs();
        let done = match op_.as_str() {
            APPROVE_SERVER => hub
                .db
                .add_gitlab(&named, &url, &principal, now)
                .map(|row| (row.url, true)),
            REJECT_SERVER => hub.db.reject_gitlab(&url, &principal, now),
            _ => hub.db.forget_gitlab(&url, &principal, now),
        };
        if let Ok((url, true)) = &done {
            crate::relays::server_changed(&hub, url)?;
        }
        Ok(done)
    })
    .await?;
    let (url, changed) = match done {
        Ok(done) => done,
        Err(e) if e.is::<GitlabRefused>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {e}."),
            ));
        }
        Err(e) => return Err(e),
    };
    let said = match (op, changed) {
        (APPROVE_SERVER, _) => format!("Approved GitLab server {url} as {name}."),
        (REJECT_SERVER, true) => format!("Rejected GitLab server {url}."),
        (REJECT_SERVER, false) => format!("GitLab server {url} was rejected already."),
        (_, true) => format!("Forgot the rejection of GitLab server {url}."),
        (_, false) => format!("GitLab server {url} was not rejected."),
    };
    if changed {
        eprintln!(
            "vk-hub: ui: {} {}",
            auth.session.principal(),
            match op {
                APPROVE_SERVER => format!("added GitLab instance {name} at {url}"),
                REJECT_SERVER => format!("rejected GitLab server {url}"),
                _ => format!("forgot rejected GitLab server {url}"),
            }
        );
    }
    if !htmx {
        return Ok(see_other(PATH));
    }
    Ok(fleet::said_so(&said))
}

/// Approve, reject or forget the projects of instance `gitlab` `form` ticks (`project`), as
/// `vk-hub gitlabs projects approve|reject|forget` do, only while the instance is still at the
/// `url` the form showed; approving or rejecting keeps the path recorded.
async fn decide_projects(
    ui: &Ui,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    op: &str,
) -> Result<Response<Body>> {
    let gitlab = field(form, "gitlab").unwrap_or("").to_string();
    let url = field(form, "url").unwrap_or("").to_string();
    let mut ids = Vec::new();
    for (_, id) in form.iter().filter(|(k, _)| k == "project") {
        match id.parse::<u64>() {
            Ok(id) if id > 0 => ids.push(id),
            _ => {
                return Ok(actions::refused(
                    htmx,
                    StatusCode::BAD_REQUEST,
                    "Refused: not a project ID.",
                ));
            }
        }
    }
    if ids.is_empty() {
        return Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "Tick at least one project.",
        ));
    }
    let (hub, principal, op_, named) = (
        ui.hub.clone(),
        auth.session.principal(),
        op.to_string(),
        gitlab.clone(),
    );
    let done = blocking(move || {
        let now = crate::now_secs();
        let refs: Vec<ProjectRef> = (ids.iter())
            .map(|&id| ProjectRef { id, path: None })
            .collect();
        let seen = (named.as_str(), url.as_str());
        Ok(match op_.as_str() {
            APPROVE_PROJECTS => {
                (hub.db).decide_projects_as_seen(seen, &refs, Decision::Approve, &principal, now)
            }
            REJECT_PROJECTS => {
                (hub.db).decide_projects_as_seen(seen, &refs, Decision::Reject, &principal, now)
            }
            _ => (hub.db).forget_projects_as_seen(seen, &ids, &principal, now),
        })
    })
    .await?;
    let n = match done {
        Ok(n) => n,
        Err(e) if e.is::<GitlabRefused>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {e}."),
            ));
        }
        Err(e) => return Err(e),
    };
    let done = match op {
        APPROVE_PROJECTS => "approved",
        REJECT_PROJECTS => "rejected",
        _ => "forgot",
    };
    if n > 0 {
        ui.hub.clients_changed();
        ui.hub.touch();
        eprintln!(
            "vk-hub: ui: {} {done} {n} project(s) of GitLab instance {gitlab}",
            auth.session.principal()
        );
    }
    if !htmx {
        return Ok(see_other(PATH));
    }
    Ok(fleet::said_so(&format!(
        "{} {n} project(s) of {gitlab}.",
        match op {
            APPROVE_PROJECTS => "Approved",
            REJECT_PROJECTS => "Rejected",
            _ => "Forgot",
        }
    )))
}

/// A redirect to `to`, after a plain form's post.
fn see_other(to: &'static str) -> Response<Body> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(to));
    resp
}

/// What a revoke or remove of the keys named `name` acts on, as `vk-hub keys revoke <name>`:
/// its working key, revoked (`revoke`), or with none working those that no longer work,
/// removed (`remove`). The op, and those keys.
fn target<'a>(views: &'a [KeyView], name: &str, now: u64) -> Option<(KeyOp, Vec<&'a KeyView>)> {
    let named = views.iter().filter(|v| v.row.name == name);
    let (working, dead): (Vec<&KeyView>, Vec<&KeyView>) = named.partition(|v| v.row.live(now));
    match (working.is_empty(), dead.is_empty()) {
        (false, _) => Some((KeyOp::Revoke, working)),
        (true, false) => Some((KeyOp::Remove, dead)),
        (true, true) => None,
    }
}

/// Revoke or remove the keys named in `form` once confirmed, as [`target`] finds them; `op`
/// must be what it would do, so a button shown before the keys changed acts on nothing, and the
/// store acts only if, as it writes, it would still do so to the keys confirmed.
async fn revoke(
    ui: &Ui,
    site: &FleetSite,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    op: KeyOp,
) -> Result<Response<Body>> {
    let name = field(form, "name").unwrap_or("").to_string();
    let hub = ui.hub.clone();
    let views = blocking(move || crate::clients::views(&hub)).await?;
    let now = crate::now_secs();
    let Some((wanted, keys)) = target(&views, &name, now) else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such key.",
        ));
    };
    if wanted != op {
        return Ok(actions::refused(
            htmx,
            StatusCode::CONFLICT,
            "Refused: it changed since you looked; look again.",
        ));
    }
    let (reservations, jobs) =
        keys.iter()
            .flat_map(|v| &v.instances)
            .fold((0usize, 0usize), |(r, j), i| {
                (
                    r.saturating_add(i.work.reservations),
                    j.saturating_add(i.work.queued)
                        .saturating_add(i.work.running),
                )
            });
    let mut detail = Html::new();
    detail.raw("<p><strong>").text(&name).raw("</strong>: ");
    for (n, v) in keys.iter().enumerate() {
        if n > 0 {
            detail.raw(", ");
        }
        detail.raw("<code>vkk_").text(&v.row.prefix).raw("…</code>");
    }
    detail
        .raw("; ")
        .text(reservations)
        .raw(" reservation(s), ")
        .text(jobs)
        .raw(" job(s) queued or running</p>");
    let ids: Vec<String> = keys.iter().map(|v| v.id.clone()).collect();
    // Back to the tab showing them.
    let back = OTHER;
    let ask = actions::Ask {
        path: PATH.to_string(),
        back: back.to_string(),
        op: op.name().to_string(),
        what: match (op, keys.len()) {
            (KeyOp::Revoke, _) => {
                "Revoke this API key? It stops working at once: whatever holds it can reserve \
                 and place nothing more, and vk-gitlab can no longer follow or settle its jobs \
                 under way."
            }
            (KeyOp::Remove, 1) => {
                "Remove this API key, which no longer works? Its client instances go with it \
                 and its name is free again; its jobs stay in the history."
            }
            (KeyOp::Remove, _) => {
                "Remove these API keys, which no longer work? Their client instances go with \
                 them and their name is free again; their jobs stay in the history."
            }
        },
        detail,
        asked: vec![("name", name.clone()), ("keys", ids.join(","))],
    };
    if let Some(asked) = actions::ask_first(&site.questions, fleet::layout, htmx, auth, form, &ask)?
    {
        return Ok(asked);
    }
    let (hub, principal, named) = (ui.hub.clone(), auth.session.principal(), name.clone());
    let done = blocking(move || {
        Ok(hub
            .db
            .revoke_api_keys_as_seen(&named, op, &ids, &principal, crate::now_secs()))
    })
    .await?;
    let done = match done {
        Ok(done) => done,
        Err(e) if e.is::<KeysChanged>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                "Refused: it changed since you were asked; look again.",
            ));
        }
        Err(e) => return Err(e),
    };
    if !done {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such key.",
        ));
    }
    ui.hub.clients_changed();
    let (said, done) = match op {
        KeyOp::Revoke => (format!("Revoked API key {name}."), "revoked"),
        KeyOp::Remove => (
            format!("Removed the API key(s) named {name} that no longer worked."),
            "removed",
        ),
    };
    eprintln!(
        "vk-hub: ui: {} {done} API key {name}",
        auth.session.principal()
    );
    if !htmx {
        return Ok(see_other(back));
    }
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">")
        .text(&said)
        .raw("</div>");
    Ok(actions::swap_none(super::html_response(StatusCode::OK, h)))
}

/// Instance `i` of key `key`: all that it said made display-safe again ([`Html::node`]), a
/// runner's URL linked only when it is a plain web link. Under a key that no longer works, the
/// key says so and the instance is never shown connected: it can no longer be.
fn instance_row(h: &mut Html, key: &KeyRow, i: &InstanceView, now: u64) {
    let r = &i.row;
    h.raw("<tr><td>").text(&key.name);
    key_gone(h, key, now);
    h.raw("</td><td>");
    or_dash(h, &r.hostname);
    h.raw("</td><td>");
    if r.instance.is_empty() {
        h.raw("<span class=\"sub\">unknown instance</span>");
    } else {
        h.raw("<code>").node(&r.instance).raw("</code>");
    }
    h.raw("</td><td>");
    or_dash(h, &format!("{} {}", r.program, r.version));
    h.raw("</td><td>");
    if r.runners.is_empty() {
        h.raw("-");
    }
    for (n, runner) in r.runners.iter().enumerate() {
        if n > 0 {
            h.raw("<br>");
        }
        h.node(&runner.name).raw(" · pool ").node(&runner.pool);
        if !runner.url.is_empty() {
            h.raw(" · ").external_link(Some(&runner.url), &runner.url);
        }
    }
    h.raw("</td><td>");
    // 0 for an instance known only by what it holds, heard from before memory recalls.
    if r.last_seen == 0 {
        h.raw("-");
    } else {
        heard_at(h, now, r.last_seen, key.live(now));
    }
    let w = i.work;
    h.raw("</td><td class=\"num\">")
        .text(w.reservations)
        .raw("</td><td class=\"num\">")
        .text(w.queued)
        .raw("</td><td class=\"num\">")
        .text(w.running)
        .raw("</td></tr>");
}

/// Show a client's `value`, or `-` if blank.
fn or_dash(h: &mut Html, value: &str) {
    match value.trim() {
        "" => h.raw("-"),
        v => h.node(v),
    };
}

/// A badge after the name of `key` when it no longer works.
fn key_gone(h: &mut Html, key: &KeyRow, now: u64) {
    if key.revoked_at.is_some() {
        h.raw(" <span class=\"badge bad\">key revoked</span>");
    } else if key.expires_at <= now {
        h.raw(" <span class=\"badge warn\">key expired</span>");
    }
}

/// When `then` was, marked connected when within [`CLIENT_ACTIVE_SECS`] of `now` through a key
/// that works (`live`).
fn heard_at(h: &mut Html, now: u64, then: u64, live: bool) {
    if live && now.saturating_sub(then) <= CLIENT_ACTIVE_SECS {
        h.raw("<span class=\"badge ok\">connected</span> ");
    }
    super::fleet::time_ago(h, now, then);
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::client::ClientRunner;

    use super::*;
    use crate::jobs::Work;
    use crate::store::{ClientRow, Scope};

    fn key(name: &str) -> KeyRow {
        KeyRow {
            name: name.into(),
            prefix: "0123abcd".into(),
            scopes: vec![Scope::Jobs, Scope::Capacity],
            pools: vec!["ci".into()],
            max_envelope: None,
            created_at: 100,
            created_by: "uid 0".into(),
            expires_at: 10_000,
            revoked_at: None,
        }
    }

    fn instance(name: &str, last_seen: u64) -> InstanceView {
        InstanceView {
            row: ClientRow {
                key_name: "gitlab".into(),
                instance: name.into(),
                first_seen: 100,
                last_seen,
                hello_at: None,
                program: String::new(),
                version: String::new(),
                hostname: String::new(),
                concurrent: None,
                runners: Vec::new(),
            },
            work: Work::default(),
        }
    }

    #[test]
    fn instances_show_what_they_said_and_whether_they_are_connected() {
        let mut said = instance("s_1", 1000);
        said.row.hostname = "ci-1".into();
        said.row.program = "vk-gitlab".into();
        said.row.version = "0.91.1".into();
        said.row.runners = vec![
            ClientRunner {
                name: "docker".into(),
                url: "https://gitlab.example.com".into(),
                pool: "ci".into(),
                labels: vec![],
                limit: None,
            },
            // The hub strips credentials before storage. If any reach the renderer,
            // show the URL as text, never as a link.
            ClientRunner {
                name: "shell".into(),
                url: "https://user:pass@gitlab.example.com".into(),
                pool: "ci".into(),
                labels: vec![],
                limit: None,
            },
        ];
        said.work = Work {
            reservations: 1,
            queued: 2,
            running: 3,
        };
        let views = [
            KeyView {
                id: "ab".repeat(32),
                row: key("gitlab"),
                instances: vec![said, instance("", 999 - CLIENT_ACTIVE_SECS)],
                jobs: 7,
            },
            KeyView {
                id: "cd".repeat(32),
                row: KeyRow {
                    revoked_at: Some(200),
                    ..key("old")
                },
                instances: Vec::new(),
                jobs: 0,
            },
            KeyView {
                id: "ef".repeat(32),
                row: KeyRow {
                    pools: vec![ANY_POOL.into()],
                    expires_at: 1000,
                    ..key("lapsed")
                },
                instances: vec![instance("gone", 0)],
                jobs: 0,
            },
        ];
        let page = fragment(&views, 1000, false).into_string();
        for want in [
            "<td>gitlab</td><td><code>vkk_0123abcd…</code></td><td>jobs, capacity</td>",
            &format!("<a href=\"/jobs?key={}\">7</a>", "ab".repeat(32)),
            "<span class=\"badge bad\">revoked</span>",
            "<td>jobs, capacity</td><td>ci</td><td>-</td><td><time",
            "</td><td>expires <time",
            "<td>lapsed</td><td><code>vkk_0123abcd…</code></td><td>jobs, capacity</td>\
             <td>any</td>",
            "<span class=\"badge warn\">expired</span>",
            // Known only by what it holds: no contact to show, for it or its key.
            "<td><code>gone</code></td><td>-</td><td>-</td><td>-</td>",
            "</td><td>-</td><td class=\"num\">0</td>",
            "<td>gitlab</td><td>ci-1</td><td><code>s_1</code></td><td>vk-gitlab 0.91.1</td>",
            "docker · pool ci · <a href=\"https://gitlab.example.com\" target=\"_blank\" \
             rel=\"noopener noreferrer\">https://gitlab.example.com</a>",
            "shell · pool ci · https://user:pass@gitlab.example.com</td>",
            "<td class=\"num\">1</td><td class=\"num\">2</td><td class=\"num\">3</td>",
            "<td>-</td><td><span class=\"sub\">unknown instance</span></td><td>-</td><td>-</td>",
        ] {
            assert!(page.contains(want), "{want}: {page}");
        }
        // Heard from just now: connected; 181 seconds ago: no longer.
        assert_eq!(page.matches("badge ok\">connected").count(), 2, "{page}");

        assert!(!page.contains("<form"), "{page}");

        let none = fragment(&[], 1000, false).into_string();
        assert!(none.contains("<code>vk-hub keys create</code>"), "{none}");
        assert!(none.contains("no client has used a key yet"), "{none}");
    }

    /// An instance seen through a key that no longer works is never shown connected, and its
    /// key says why. The same instance shown under a working key, holding nothing, is not
    /// shown again: it is the client that moved to the new key.
    #[test]
    fn instances_of_a_key_that_no_longer_works_are_not_live() {
        let view = |id: &str, row: KeyRow, instances| KeyView {
            id: id.repeat(32),
            row,
            instances,
            jobs: 0,
        };
        let mut holding = instance("s_2", 990);
        holding.work.running = 1;
        let views = [
            view(
                "ab",
                KeyRow {
                    revoked_at: Some(500),
                    ..key("vk-gitlab")
                },
                vec![instance("s_1", 990), holding],
            ),
            view(
                "cd",
                KeyRow {
                    created_at: 500,
                    ..key("vk-gitlab")
                },
                vec![instance("s_1", 995)],
            ),
        ];
        let page = fragment(&views, 1000, false).into_string();
        assert_eq!(page.matches("<code>s_1</code>").count(), 1, "{page}");
        assert!(
            page.contains(
                "<td>vk-gitlab <span class=\"badge bad\">key revoked</span></td><td>-</td>\
                 <td><code>s_2</code>"
            ),
            "{page}"
        );
        // The working key's row and its instance only.
        assert_eq!(page.matches("badge ok\">connected").count(), 2, "{page}");
        // The revoked key counts the instance it shows, not the one that moved on.
        let revoked = page.split("<td>vk-gitlab</td>").nth(1).unwrap();
        let revoked = revoked.split("</tr>").next().unwrap();
        assert!(revoked.contains("<td class=\"num\">1</td>"), "{revoked}");

        // Without a working key showing it, it is shown, marked.
        let page = fragment(&views[..1], 1000, false).into_string();
        assert_eq!(page.matches("<code>s_1</code>").count(), 1, "{page}");
        assert!(!page.contains("connected"), "{page}");
    }

    /// An operator's fragment offers to revoke a working key, and to remove one that no
    /// longer works only when no working key holds its name: removing acts on the name.
    #[test]
    fn an_operator_revokes_working_keys_and_removes_dead_ones() {
        let view = |id: &str, row: KeyRow| KeyView {
            id: id.repeat(32),
            row,
            instances: Vec::new(),
            jobs: 0,
        };
        let views = [
            view("ab", key("gitlab")),
            view(
                "cd",
                KeyRow {
                    revoked_at: Some(200),
                    ..key("gitlab")
                },
            ),
            view(
                "ef",
                KeyRow {
                    expires_at: 1000,
                    ..key("old")
                },
            ),
        ];
        let page = fragment(&views, 1000, true).into_string();
        assert_eq!(page.matches(">Revoke</button>").count(), 1, "{page}");
        assert_eq!(page.matches(">Remove</button>").count(), 1, "{page}");
        assert!(
            page.contains("name=\"name\" value=\"old\"><button class=\"danger\">Remove"),
            "{page}"
        );
        assert!(!page.contains("_csrf"), "{page}");
        assert_eq!(
            target(&views, "gitlab", 1000).map(|(op, k)| (op, k.len())),
            Some((KeyOp::Revoke, 1))
        );
        assert_eq!(
            target(&views, "old", 1000).map(|(op, k)| (op, k.len())),
            Some((KeyOp::Remove, 1))
        );
        assert!(target(&views, "none", 1000).is_none());

        // Several that no longer work under one name: one button, on the newest, removing all.
        let views = [
            view(
                "ab",
                KeyRow {
                    revoked_at: Some(200),
                    ..key("gitlab")
                },
            ),
            view(
                "cd",
                KeyRow {
                    created_at: 300,
                    expires_at: 1000,
                    ..key("gitlab")
                },
            ),
            view(
                "ef",
                KeyRow {
                    created_at: 200,
                    revoked_at: Some(250),
                    ..key("gitlab")
                },
            ),
        ];
        let page = fragment(&views, 1000, true).into_string();
        assert_eq!(page.matches(">Remove</button>").count(), 1, "{page}");
        let newest = page.split("<td>gitlab</td>").nth(2).unwrap();
        let newest = newest.split("</tr>").next().unwrap();
        assert!(newest.contains(">Remove</button>"), "{page}");
        assert_eq!(
            target(&views, "gitlab", 1000).map(|(op, k)| (op, k.len())),
            Some((KeyOp::Remove, 3))
        );
    }
}
