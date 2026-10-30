//! Capacity policy pages for viewers and operators: the whole policy at [`PATH`], tenants at
//! [`tenant_path`], and each project's share on its page ([`project_section`]). Operators edit
//! them with a form per change, each beside what it changes, posted to [`PATH`]: a tenant's
//! share, the projects it lists and the runners mapped to it; a project's production branches
//! and placement rules in every tenant listing it; the fallback tenant, API clients'
//! assignments, scheduling settings and headroom; or, folded away, the whole policy in
//! `vk-hub capacity-policy set` format. Pickers offer the projects, runners and API keys the hub
//! knows; a folded form takes a project or runner it has not seen yet by instance and ID.
//!
//! Adding a tenant uses the current policy and rereads once if another edit stores first.
//! Other edits use the displayed policy and are refused as stale if its digest has changed.
//! Each edit uses the CLI's validation and [`crate::store::Db::replace_capacity_policy_if`],
//! which rechecks the digest and audits changes in the same transaction.
//! All but adding a tenant ask first ([`actions::ask_first`]), saying what would change
//! ([`describe`]): any of them may keep jobs from running.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use anyhow::{Context, Result, bail};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::client::Placement;
use vk_hub_proto::job::Envelope;

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, field, message, page};
use crate::policy::{Class, Headroom, PlacementRule, Policy, Project, RunnerMapping, Tenant};
use crate::server::Hub;
use crate::store::{PolicyRefused, ProjectState, ProjectView, Role, policy_changes};

/// The whole policy's page, and where its editors post.
pub(super) const PATH: &str = "/capacity";

const TENANTS: &str = "/capacity/tenants/";

/// The policy's and tenants' pages before the navigation had sections.
const OLD_PATH: &str = "/clients/capacity";
const OLD_TENANTS: &str = "/clients/tenants/";

/// The largest edit posted: a policy the admin socket takes (64 KiB), as a browser posts it.
/// Pretty-printed and urlencoded, with 3 bytes for each `"`, `:`, `,`, brace and bracket and 6
/// for each CRLF, a policy grows about 2.9 times for runner mappings and 4 for nested short
/// branch globs. Each of [`actions`]' questions holds the edit it asks about: up to
/// `MAX_QUESTIONS` (1024) times this, 384 MiB, all of operators.
const MAX_FORM: usize = 6 * 64 * 1024;

/// Replace the whole policy: `policy`.
const SET_POLICY: &str = "capacity-policy";
/// Add a tenant of weight 1 with no projects nor runners: `tenant`.
const ADD_TENANT: &str = "capacity-add-tenant";
/// Remove a tenant other than the fallback, unmapping its runners and sending its API clients
/// to the fallback: `tenant`.
const REMOVE_TENANT: &str = "capacity-remove-tenant";
/// Set a tenant's weight and cap, none when empty: `tenant`, `weight`, `cap`.
const SET_SHARE: &str = "capacity-share";
/// List a project for a tenant, with the branches and rules other tenants list it with:
/// `tenant`, [`target`] `project`, `from`.
const ADD_PROJECT: &str = "capacity-add-project";
/// Stop listing a project for a tenant: `tenant`, [`target`] `project`, `from`.
const REMOVE_PROJECT: &str = "capacity-remove-project";
/// Map a runner to a tenant as a class, wherever it was mapped: `tenant`, [`target`]
/// `runner`, `class`.
const MAP_RUNNER: &str = "capacity-runner";
/// Unmap a runner from a tenant: `tenant`, [`target`] `runner`.
const UNMAP_RUNNER: &str = "capacity-unmap-runner";
/// Make a tenant the fallback: `tenant`.
const SET_FALLBACK: &str = "capacity-fallback";
/// Charge an API client to a tenant, or to the fallback when empty: `principal`, `tenant`.
const SET_CLIENT: &str = "capacity-client";
/// Set the scheduling settings: `probe_limit`, `production_probe_burst`,
/// `backoff_initial_secs`, `backoff_max_secs`, `busy_secs`.
const SET_SCHEDULING: &str = "capacity-scheduling";
/// Add a headroom entry: `pool`, `labels`, `slots`, `mem_mib`, `cpus`, `disk_gib`.
const ADD_HEADROOM: &str = "capacity-add-headroom";
/// Remove headroom entry `index`.
const REMOVE_HEADROOM: &str = "capacity-remove-headroom";
/// Set a project's production branches, one per line: `tenant`, `gitlab`, `project`,
/// `branches`.
const SET_BRANCHES: &str = "capacity-branches";
/// Add a placement rule to a project, each list one per line: `tenant`, `gitlab`, `project`,
/// `branches`, `nodes`, `pools`.
const ADD_RULE: &str = "capacity-add-rule";
/// Remove a project's placement rule `index`, as `tenant` lists it: `tenant`, `gitlab`,
/// `project`, `index`.
const REMOVE_RULE: &str = "capacity-remove-rule";

/// `from`'s value on a project's page: its edits lead back there.
const FROM_PROJECT: &str = "project";

/// Why an edit based on a replaced policy is refused.
const STALE: &str = "the capacity policy changed since this page was shown; reload it and retry";

/// The most changes a question lists; the rest are counted.
const MAX_DESCRIBED: usize = 50;

/// Tenant `name`'s page.
pub(super) fn tenant_path(name: &str) -> String {
    format!("{TENANTS}{name}")
}

/// Map a policy or tenant page's `path` from before navigation sections to its current page.
pub(super) fn moved(path: &str) -> Option<String> {
    if path == OLD_PATH {
        return Some(PATH.to_string());
    }
    let name = path.strip_prefix(OLD_TENANTS)?;
    crate::store::valid_name(name).then(|| tenant_path(name))
}

/// The tenant named by the page at `path`.
pub(super) fn tenant_target(path: &str) -> Option<&str> {
    let name = path.strip_prefix(TENANTS)?;
    crate::store::valid_name(name).then_some(name)
}

/// What a page says in place of a policy this hub cannot read.
fn unreadable(h: &mut Html, error: &anyhow::Error) {
    h.raw("<p class=\"message\">")
        .text(format!("{error:#}"))
        .raw("</p>");
}

/// A runner a relay reports, by its approved instance's name and GitLab ID.
struct KnownRunner {
    gitlab: String,
    id: u64,
    /// Its name in the relay's config.
    name: String,
    /// The relay's host.
    relay: String,
}

/// What the hub knows besides the policy, named on its pages and offered by its pickers.
struct Known {
    gitlabs: Vec<String>,
    projects: Vec<ProjectView>,
    runners: Vec<KnownRunner>,
    /// Each API key's principal ID and name.
    keys: Vec<(String, String)>,
}

impl Known {
    /// Reads the database: call off the runtime.
    fn read(hub: &Hub) -> Result<Self> {
        let mut runners = Vec::new();
        for relay in crate::relays::views(hub)? {
            let Some(gitlab) = relay.server.as_ref().and_then(|s| s.name.clone()) else {
                continue;
            };
            for runner in relay.row.inventory.iter().flat_map(|i| &i.runners) {
                if let Some(id) = runner.runner_id {
                    runners.push(KnownRunner {
                        gitlab: gitlab.clone(),
                        id,
                        name: runner.name.clone(),
                        relay: relay.row.hostname.clone(),
                    });
                }
            }
        }
        runners.sort_by(|a, b| (&a.gitlab, a.id).cmp(&(&b.gitlab, b.id)));
        runners.dedup_by(|a, b| (&a.gitlab, a.id) == (&b.gitlab, b.id));
        Ok(Known {
            gitlabs: hub
                .db
                .gitlabs()?
                .into_iter()
                .map(|(name, _)| name)
                .collect(),
            projects: hub.db.gitlab_projects(None)?,
            runners,
            keys: (hub.db.api_keys_with_ids()?.into_iter())
                .map(|(id, key)| (id, key.name))
                .collect(),
        })
    }

    fn project(&self, gitlab: &str, id: u64) -> Option<&ProjectView> {
        self.projects
            .iter()
            .find(|p| p.gitlab == gitlab && p.id == id)
    }

    fn runner(&self, gitlab: &str, id: u64) -> Option<&KnownRunner> {
        self.runners
            .iter()
            .find(|r| r.gitlab == gitlab && r.id == id)
    }
}

/// Project `id` of `gitlab` as a page names it: its path where known, linking to its page.
fn project_link(h: &mut Html, known: &Known, gitlab: &str, id: u64) {
    h.raw("<a href=\"")
        .text(super::projects::path(gitlab, id))
        .raw("\">");
    match known.project(gitlab, id).filter(|p| !p.row.path.is_empty()) {
        Some(p) => h.node(&p.row.path),
        None => h.text(format_args!("project {id}")),
    };
    h.raw("</a>");
}

fn approval_badge(h: &mut Html, project: Option<&ProjectView>) {
    h.raw(match project.map(|p| p.row.state) {
        Some(ProjectState::Approved) => "<span class=\"badge ok\">approved</span>",
        Some(ProjectState::Pending) => "<span class=\"badge warn\">pending</span>",
        Some(ProjectState::Rejected) => "<span class=\"badge bad\">rejected</span>",
        None => "<span class=\"badge\">never seen</span>",
    });
}

/// `GET /capacity`.
pub(super) async fn policy_get(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let (policy, known) =
        blocking(move || Ok((hub.db.capacity_policy(), Known::read(&hub)?))).await?;
    let mut main = Html::new();
    main.raw("<h1>Capacity policy</h1><p class=\"sub\">How the hub shares the fleet: each ")
        .raw("relay runner's requests and each API key's reservations are charged to a tenant, ")
        .raw("and the tenant holding the least for its weight goes first, up to its cap. A ")
        .raw("runner gets work only once mapped to a tenant, and only for the projects that ")
        .raw("tenant lists.</p>");
    let policy = match policy {
        Ok(policy) => policy,
        Err(e) => {
            unreadable(&mut main, &e);
            return Ok(page(fleet::layout("Capacity policy", PATH, auth, &main)));
        }
    };
    let steer = auth.session.role >= Role::Operator;
    let digest = policy.digest()?;
    main.raw("<section><h2>Tenants</h2>");
    tenants_table(&mut main, &policy);
    if steer {
        add_tenant_fields(&mut main, auth);
    }
    main.raw("</section>");
    fallback_section(&mut main, &policy, auth, &digest, steer);
    clients_section(&mut main, &policy, &known, auth, &digest, steer);
    scheduling_section(&mut main, &policy, auth, &digest, steer);
    headroom_section(&mut main, &policy, auth, &digest, steer);
    let json = serde_json::to_string_pretty(&policy)?;
    main.raw("<section><details class=\"fold\"><summary>The whole policy as JSON</summary>")
        .raw("<p class=\"sub\">As <code>vk-hub capacity-policy show</code> prints it and ")
        .raw("<code>vk-hub capacity-policy set</code> takes it.</p>");
    if steer {
        edit_form(&mut main, auth, SET_POLICY, &digest);
        main.raw("<textarea name=\"policy\" rows=\"24\" spellcheck=\"false\" ")
            .raw("aria-label=\"Policy (JSON)\">")
            .text(json)
            .raw("</textarea><button>Replace the whole policy</button></form>");
    } else {
        main.raw("<pre>").text(json).raw("</pre>");
    }
    main.raw("</details></section>");
    Ok(page(fleet::layout("Capacity policy", PATH, auth, &main)))
}

/// Each tenant's weight and cap, and how many projects, runners and API clients it has,
/// linking to its page.
fn tenants_table(h: &mut Html, policy: &Policy) {
    h.raw("<table class=\"grid\"><thead><tr><th>tenant</th><th class=\"num\">weight</th>")
        .raw("<th>cap</th><th class=\"num\">projects</th><th class=\"num\">runners</th>")
        .raw("<th class=\"num\">API clients</th></tr></thead><tbody>");
    for (name, tenant) in &policy.tenants {
        h.raw("<tr><td><a href=\"")
            .text(tenant_path(name))
            .raw("\">")
            .text(name)
            .raw("</a>");
        if policy.fallback == *name {
            h.raw(" <span class=\"sub\">fallback</span>");
        }
        h.raw("</td><td class=\"num\">")
            .text(tenant.weight)
            .raw("</td><td>")
            .text(cap(tenant))
            .raw("</td><td class=\"num\">")
            .text(tenant.projects.len())
            .raw("</td><td class=\"num\">")
            .text(policy.runners.iter().filter(|r| r.tenant == *name).count())
            .raw("</td><td class=\"num\">")
            .text(policy.clients.values().filter(|t| *t == name).count())
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

fn fallback_section(h: &mut Html, policy: &Policy, auth: &Auth, digest: &str, steer: bool) {
    h.raw("<section><h2>Fallback tenant</h2><p class=\"sub\">API keys assigned no tenant ")
        .raw("below are charged to it. Relay runners never fall back: an unmapped runner gets ")
        .raw("no work.</p>");
    if !steer {
        h.raw("<p><a href=\"")
            .text(tenant_path(&policy.fallback))
            .raw("\">")
            .text(&policy.fallback)
            .raw("</a></p></section>");
        return;
    }
    edit_form(h, auth, SET_FALLBACK, digest);
    h.raw("<label>Tenant <select name=\"tenant\">");
    tenant_options(h, policy, &policy.fallback);
    h.raw("</select></label><button>Save fallback</button></form></section>");
}

/// An `<option>` of each tenant, `selected` the one selected.
fn tenant_options(h: &mut Html, policy: &Policy, selected: &str) {
    for name in policy.tenants.keys() {
        h.raw("<option value=\"").text(name).raw("\"");
        if name == selected {
            h.raw(" selected");
        }
        h.raw(">").text(name).raw("</option>");
    }
}

/// API keys and the tenants they are charged to, including policy assignments for keys the
/// hub no longer has.
fn clients_section(
    h: &mut Html,
    policy: &Policy,
    known: &Known,
    auth: &Auth,
    digest: &str,
    steer: bool,
) {
    h.raw("<section><h2>API clients</h2><p class=\"sub\">The tenant each API key's ")
        .raw("reservations are charged to, by its principal ID. Their work is always normal, ")
        .raw("never production.</p>");
    let mut rows: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for (id, name) in &known.keys {
        rows.insert(id, Some(name));
    }
    for principal in policy.clients.keys() {
        rows.entry(principal).or_insert(None);
    }
    if rows.is_empty() {
        h.raw("<p class=\"empty\">No API key yet.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>key</th><th>principal ID</th>")
            .raw("<th>tenant</th></tr></thead><tbody>");
        for (principal, name) in &rows {
            h.raw("<tr><td>");
            match name {
                Some(name) => h.text(name),
                None => h.raw("<span class=\"sub\">not a key the hub has</span>"),
            };
            h.raw("</td><td><code>")
                .text(principal)
                .raw("</code></td><td>");
            let assigned = policy.clients.get(*principal);
            if steer {
                edit_form_class(h, auth, SET_CLIENT, digest, "inline");
                hidden(h, "principal", principal);
                h.raw("<select name=\"tenant\" aria-label=\"Tenant\"><option value=\"\">")
                    .text(format_args!("the fallback ({})", policy.fallback))
                    .raw("</option>");
                tenant_options(h, policy, assigned.map_or("", String::as_str));
                h.raw("</select><button>Save</button></form>");
            } else {
                match assigned {
                    Some(tenant) => h
                        .raw("<a href=\"")
                        .text(tenant_path(tenant))
                        .raw("\">")
                        .text(tenant)
                        .raw("</a>"),
                    None => h
                        .raw("<span class=\"sub\">the fallback, ")
                        .text(&policy.fallback)
                        .raw("</span>"),
                };
            }
            h.raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section>");
}

fn scheduling_section(h: &mut Html, policy: &Policy, auth: &Auth, digest: &str, steer: bool) {
    h.raw("<section><h2>Scheduling</h2><p class=\"sub\">A runner that took no job for the ")
        .raw("busy time probes GitLab, at most the probe limit fleet-wide. One that finds no ")
        .raw("job backs off from the initial backoff, doubling up to the maximum. After the ")
        .raw("production probe burst, normal work goes before the next production probe.</p>");
    let fields: [(&'static str, &'static str, u64, &'static str); 5] = [
        ("busy_secs", "Busy time", policy.busy_secs, " s"),
        ("probe_limit", "Probe limit", policy.probe_limit.into(), ""),
        (
            "production_probe_burst",
            "Production probe burst",
            policy.production_probe_burst.into(),
            "",
        ),
        (
            "backoff_initial_secs",
            "Initial backoff",
            policy.backoff_initial_secs,
            " s",
        ),
        (
            "backoff_max_secs",
            "Maximum backoff",
            policy.backoff_max_secs,
            " s",
        ),
    ];
    if !steer {
        h.raw("<table class=\"kv\"><tbody>");
        for (_, label, value, unit) in fields {
            pages::kv(h, label, &format!("{value}{unit}"));
        }
        h.raw("</tbody></table></section>");
        return;
    }
    edit_form(h, auth, SET_SCHEDULING, digest);
    for (name, label, value, unit) in fields {
        h.raw("<label>")
            .raw(label)
            .raw(" <input type=\"number\" min=\"1\" required name=\"")
            .raw(name)
            .raw("\" value=\"")
            .text(value)
            .raw("\">")
            .raw(unit)
            .raw("</label>");
    }
    h.raw("<button>Save scheduling</button></form></section>");
}

fn headroom_section(h: &mut Html, policy: &Policy, auth: &Auth, digest: &str, steer: bool) {
    h.raw("<section><h2>Production headroom</h2><p class=\"sub\">Room kept for production ")
        .raw("work: normal work leaves the fleet this many envelopes of each placement, or all ")
        .raw("the room left when already short.</p>");
    if policy.headroom.is_empty() {
        h.raw("<p class=\"empty\">None: normal work may take all the room.</p>");
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
                button_form(
                    h,
                    auth,
                    REMOVE_HEADROOM,
                    digest,
                    &[("index", i.to_string())],
                    "Remove",
                );
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    if steer {
        h.raw("<h3>Keep room</h3>");
        edit_form(h, auth, ADD_HEADROOM, digest);
        h.raw("<label>Slots <input type=\"number\" name=\"slots\" min=\"1\" value=\"1\" ")
            .raw("required></label><label>Pool <input name=\"pool\" required></label>")
            .raw("<label>Labels <input name=\"labels\" placeholder=\"comma- or space-separated\">")
            .raw("</label><label>Memory <input type=\"number\" name=\"mem_mib\" min=\"1\" ")
            .raw("required> MiB</label><label>CPUs <input type=\"number\" name=\"cpus\" ")
            .raw("min=\"1\" required></label><label>Disk <input type=\"number\" ")
            .raw("name=\"disk_gib\" min=\"0\" value=\"0\" required> GiB</label>")
            .raw("<button>Add headroom</button></form>");
    }
    h.raw("</section>");
}

/// `GET /capacity/tenants/<name>`.
pub(super) async fn tenant_get(name: &str, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let (policy, known) =
        blocking(move || Ok((hub.db.capacity_policy(), Known::read(&hub)?))).await?;
    let mut main = Html::new();
    main.raw("<h1>Tenant ").text(name);
    let policy = match policy {
        Ok(policy) => policy,
        Err(e) => {
            main.raw("</h1>");
            unreadable(&mut main, &e);
            return Ok(tenant_page(name, auth, &main));
        }
    };
    let Some(tenant) = policy.tenant(name) else {
        return Ok(message(StatusCode::NOT_FOUND, "No such capacity tenant."));
    };
    if policy.fallback == name {
        main.raw(" <span class=\"badge\">fallback</span>");
    }
    main.raw("</h1><p><a href=\"")
        .raw(PATH)
        .raw("\">Capacity policy</a></p>");
    let steer = auth.session.role >= Role::Operator;
    let digest = policy.digest()?;
    share_section(&mut main, name, tenant, auth, &digest, steer);
    projects_section(
        &mut main, name, tenant, &policy, &known, auth, &digest, steer,
    );
    runners_section(&mut main, name, &policy, &known, auth, &digest, steer);
    main.raw("<section><h2>API clients</h2>");
    let clients: Vec<_> = (policy.clients.iter())
        .filter(|(_, t)| *t == name)
        .map(|(principal, _)| principal)
        .collect();
    if clients.is_empty() {
        main.raw("<p class=\"empty\">None");
        if policy.fallback == name {
            main.raw(" assigned, but every API key assigned no tenant is charged to it");
        }
        main.raw(".</p>");
    } else {
        main.raw("<table class=\"grid\"><thead><tr><th>key</th><th>principal ID</th></tr>")
            .raw("</thead><tbody>");
        for principal in clients {
            main.raw("<tr><td>");
            match known.keys.iter().find(|(id, _)| id == principal) {
                Some((_, key)) => main.text(key),
                None => main.raw("<span class=\"sub\">not a key the hub has</span>"),
            };
            main.raw("</td><td><code>")
                .text(principal)
                .raw("</code></td></tr>");
        }
        main.raw("</tbody></table>");
    }
    main.raw("<p class=\"sub\">API keys are assigned on the <a href=\"")
        .raw(PATH)
        .raw("\">capacity policy</a>'s page.</p></section>");
    if steer && policy.fallback != name {
        main.raw("<section class=\"steer\"><div class=\"groups\"><div class=\"group danger\">")
            .raw("<h3>Remove tenant</h3><p class=\"does\">Its runners are unmapped and get no ")
            .raw("work; its API keys go to the fallback tenant.</p>");
        edit_form_class(&mut main, auth, REMOVE_TENANT, &digest, "act");
        hidden(&mut main, "tenant", name);
        main.raw("<button class=\"danger\">Remove tenant</button></form></div></div></section>");
    }
    Ok(tenant_page(name, auth, &main))
}

fn share_section(
    h: &mut Html,
    name: &str,
    tenant: &Tenant,
    auth: &Auth,
    digest: &str,
    steer: bool,
) {
    h.raw("<section><h2>Share</h2><p class=\"sub\">The hub hands room to the tenant holding ")
        .raw("the least for its weight; a tenant of weight 2 gets twice the room of one of ")
        .raw("weight 1 when both have work, and an idle tenant's share goes to the others. A cap ")
        .raw("holds it at that many requests and jobs at once.</p>");
    if !steer {
        h.raw("<table class=\"kv\"><tbody>");
        pages::kv(h, "Weight", &tenant.weight.to_string());
        pages::kv(h, "Cap", &cap(tenant));
        h.raw("</tbody></table></section>");
        return;
    }
    edit_form(h, auth, SET_SHARE, digest);
    hidden(h, "tenant", name);
    h.raw("<label>Weight <input type=\"number\" name=\"weight\" min=\"1\" required value=\"")
        .text(tenant.weight)
        .raw("\"></label><label>Cap <input type=\"number\" name=\"cap\" min=\"1\" ")
        .raw("placeholder=\"unbounded\" value=\"");
    if let Some(cap) = tenant.cap {
        h.text(cap);
    }
    h.raw("\"></label><button>Save share</button></form></section>");
}

#[allow(clippy::too_many_arguments)]
fn projects_section(
    h: &mut Html,
    name: &str,
    tenant: &Tenant,
    policy: &Policy,
    known: &Known,
    auth: &Auth,
    digest: &str,
    steer: bool,
) {
    h.raw("<section><h2>Projects</h2><p class=\"sub\">Its runners take jobs of these ")
        .raw("projects only. Production branches and placement rules are set on each ")
        .raw("project's page, the same in every tenant listing it.</p>");
    if tenant.projects.is_empty() {
        h.raw("<p class=\"empty\">None: its runners' jobs are refused.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>project</th><th>instance</th>")
            .raw("<th class=\"num\">GitLab ID</th><th>approval</th><th>production branches</th>")
            .raw("<th class=\"num\">placement rules</th>");
        if steer {
            h.raw("<th></th>");
        }
        h.raw("</tr></thead><tbody>");
        for p in &tenant.projects {
            h.raw("<tr><td>");
            project_link(h, known, &p.gitlab, p.id);
            h.raw("</td><td>")
                .text(&p.gitlab)
                .raw("</td><td class=\"num\">")
                .text(p.id)
                .raw("</td><td>");
            approval_badge(h, known.project(&p.gitlab, p.id));
            h.raw("</td><td>");
            if p.production_branches.is_empty() {
                h.raw("<span class=\"sub\">none</span>");
            } else {
                h.raw("<code>")
                    .text(p.production_branches.join(", "))
                    .raw("</code>");
            }
            h.raw("</td><td class=\"num\">")
                .text(p.placement_rules.len())
                .raw("</td>");
            if steer {
                h.raw("<td class=\"actions\">");
                button_form(
                    h,
                    auth,
                    REMOVE_PROJECT,
                    digest,
                    &[
                        ("tenant", name.to_owned()),
                        ("gitlab", p.gitlab.clone()),
                        ("project", p.id.to_string()),
                    ],
                    "Remove",
                );
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    if !steer {
        h.raw("</section>");
        return;
    }
    h.raw("<h3>Add a project</h3>");
    let listed = |p: &ProjectView| policy.project(name, &p.gitlab, p.id).is_some();
    let mut offered: Vec<_> = known.projects.iter().filter(|p| !listed(p)).collect();
    offered.sort_by(|a, b| (&a.gitlab, &a.row.path, a.id).cmp(&(&b.gitlab, &b.row.path, b.id)));
    if !offered.is_empty() {
        edit_form(h, auth, ADD_PROJECT, digest);
        hidden(h, "tenant", name);
        h.raw("<select name=\"project\" aria-label=\"Project\" required>");
        for p in offered {
            h.raw("<option value=\"")
                .text(format_args!("{}/{}", p.gitlab, p.id))
                .raw("\">");
            if p.row.path.is_empty() {
                h.text(format_args!("project {}", p.id));
            } else {
                h.node(&p.row.path);
            }
            h.text(format_args!(" · {} #{}", p.gitlab, p.id))
                .raw(match p.row.state {
                    ProjectState::Approved => "",
                    ProjectState::Pending => " (pending approval)",
                    ProjectState::Rejected => " (rejected)",
                })
                .raw("</option>");
        }
        h.raw("</select><button>Add project</button></form>");
    }
    h.raw("<details class=\"more\"><summary>A project the hub has not seen</summary>");
    if by_id_form(
        h,
        auth,
        known,
        ADD_PROJECT,
        digest,
        name,
        "project",
        "Project ID",
    ) {
        h.raw("<button>Add project</button></form>");
    }
    h.raw("</details></section>");
}

/// A form posting `op` for tenant `name`, with a picker of known instances and an ID entered
/// in `id_field`. Returns whether it opened a form, left open; no known instance means no form.
#[allow(clippy::too_many_arguments)]
fn by_id_form(
    h: &mut Html,
    auth: &Auth,
    known: &Known,
    op: &'static str,
    digest: &str,
    name: &str,
    id_field: &'static str,
    id_label: &'static str,
) -> bool {
    if known.gitlabs.is_empty() {
        h.raw("<p class=\"empty\">No GitLab instance yet.</p>");
        return false;
    }
    edit_form(h, auth, op, digest);
    hidden(h, "tenant", name);
    h.raw("<label>GitLab instance <select name=\"gitlab\" required>");
    for gitlab in &known.gitlabs {
        h.raw("<option>").text(gitlab).raw("</option>");
    }
    h.raw("</select></label><label>")
        .raw(id_label)
        .raw(" <input type=\"number\" name=\"")
        .raw(id_field)
        .raw("\" min=\"1\" required></label>");
    true
}

fn runners_section(
    h: &mut Html,
    name: &str,
    policy: &Policy,
    known: &Known,
    auth: &Auth,
    digest: &str,
    steer: bool,
) {
    h.raw("<section><h2>Runners</h2><p class=\"sub\">Relay runners charged to it, by GitLab ")
        .raw("runner ID. A production runner's work goes before normal work, and takes jobs ")
        .raw("only of its projects' production branches.</p>");
    let runners: Vec<_> = policy.runners.iter().filter(|r| r.tenant == name).collect();
    if runners.is_empty() {
        h.raw("<p class=\"empty\">None: it gets no relay work.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>runner</th><th>relay</th>")
            .raw("<th>instance</th><th class=\"num\">GitLab ID</th><th>class</th>");
        if steer {
            h.raw("<th></th>");
        }
        h.raw("</tr></thead><tbody>");
        for r in &runners {
            let seen = known.runner(&r.gitlab, r.runner_id);
            h.raw("<tr><td>");
            match seen {
                Some(seen) => h.node(&seen.name).raw("</td><td>").node(&seen.relay),
                None => h.raw("<span class=\"sub\">no relay reports it</span></td><td>-"),
            };
            h.raw("</td><td>")
                .text(&r.gitlab)
                .raw("</td><td class=\"num\">")
                .text(r.runner_id)
                .raw("</td><td>")
                .text(r.class)
                .raw("</td>");
            if steer {
                let key = [
                    ("tenant", name.to_owned()),
                    ("gitlab", r.gitlab.clone()),
                    ("runner", r.runner_id.to_string()),
                ];
                h.raw("<td class=\"actions\">");
                let (other, label) = match r.class {
                    Class::Normal => ("production", "Make production"),
                    Class::Production => ("normal", "Make normal"),
                };
                let mut fields = key.to_vec();
                fields.push(("class", other.to_owned()));
                button_form(h, auth, MAP_RUNNER, digest, &fields, label);
                button_form(h, auth, UNMAP_RUNNER, digest, &key, "Unmap");
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    if !steer {
        h.raw("</section>");
        return;
    }
    h.raw("<h3>Map a runner</h3>");
    let offered: Vec<_> = (known.runners.iter())
        .filter(|k| {
            policy
                .runner(&k.gitlab, k.id)
                .is_none_or(|m| m.tenant != name)
        })
        .collect();
    let class_select = |h: &mut Html| {
        h.raw("<select name=\"class\" aria-label=\"Class\"><option>normal</option>")
            .raw("<option>production</option></select>");
    };
    if !offered.is_empty() {
        edit_form(h, auth, MAP_RUNNER, digest);
        hidden(h, "tenant", name);
        h.raw("<select name=\"runner\" aria-label=\"Runner\" required>");
        for k in offered {
            h.raw("<option value=\"")
                .text(format_args!("{}/{}", k.gitlab, k.id))
                .raw("\">")
                .node(&k.name)
                .raw(" on ")
                .node(&k.relay)
                .text(format_args!(" · {} #{}", k.gitlab, k.id));
            match policy.runner(&k.gitlab, k.id) {
                Some(m) => h.text(format_args!(" (moves from {})", m.tenant)),
                None => h.raw(" (unmapped)"),
            };
            h.raw("</option>");
        }
        h.raw("</select>");
        class_select(h);
        h.raw("<button>Map runner</button></form>");
    } else if known.runners.is_empty() {
        h.raw("<p class=\"empty\">No relay reports a runner with its GitLab ID yet.</p>");
    }
    h.raw("<details class=\"more\"><summary>A runner no relay reports</summary>");
    if by_id_form(
        h,
        auth,
        known,
        MAP_RUNNER,
        digest,
        name,
        "runner",
        "Runner ID",
    ) {
        class_select(h);
        h.raw("<button>Map runner</button></form>");
    }
    h.raw("</details></section>");
}

/// Tenant `name`'s page around `main`.
fn tenant_page(name: &str, auth: &Auth, main: &Html) -> Response<Body> {
    page(fleet::layout(
        &format!("Tenant {name}"),
        &tenant_path(name),
        auth,
        main,
    ))
}

/// A tenant's cap, as shown.
pub(super) fn cap(tenant: &Tenant) -> String {
    tenant
        .cap
        .map_or_else(|| "unbounded".into(), |n| n.to_string())
}

/// A form posting `op` to [`PATH`] against the policy of digest `expected`, left open.
fn edit_form(h: &mut Html, auth: &Auth, op: &'static str, expected: &str) {
    edit_form_class(h, auth, op, expected, "wide");
}

/// [`edit_form`] of class `class`.
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

/// A hidden field.
fn hidden(h: &mut Html, name: &'static str, value: impl Display) {
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

/// The form adding a tenant, on the policy's page.
fn add_tenant_fields(h: &mut Html, auth: &Auth) {
    h.raw("<form class=\"wide\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\">");
    csrf_field(h, auth);
    hidden(h, "op", ADD_TENANT);
    h.raw("<label>Name <input name=\"tenant\" required></label>")
        .raw("<button>Add tenant</button></form><p class=\"sub\">Of weight 1, with no ")
        .raw("projects nor runners until its page gives it some.</p>");
}

/// A project's section of its page: the tenants listing it and their runners on its instance,
/// its production branches and its placement rules, which operators edit there.
pub(super) fn project_section(
    h: &mut Html,
    policy: &Result<Policy>,
    gitlab: &str,
    id: u64,
    auth: &Auth,
) -> Result<()> {
    h.raw("<section><h2>Capacity</h2>");
    let policy = match policy {
        Ok(policy) => policy,
        Err(e) => {
            unreadable(h, e);
            h.raw("</section>");
            return Ok(());
        }
    };
    let steer = auth.session.role >= Role::Operator;
    let digest = policy.digest()?;
    let listing: Vec<_> = (policy.tenants.iter())
        .filter_map(|(name, t)| Some((name, t, policy.project(name, gitlab, id)?)))
        .collect();
    let project_fields = |tenant: &str| {
        vec![
            ("tenant", tenant.to_owned()),
            ("gitlab", gitlab.to_owned()),
            ("project", id.to_string()),
            ("from", FROM_PROJECT.to_owned()),
        ]
    };
    if listing.is_empty() {
        h.raw("<p>No capacity tenant lists it: its relay jobs are refused.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>tenant</th><th class=\"num\">weight</th>")
            .raw("<th>cap</th><th>runners</th>");
        if steer {
            h.raw("<th></th>");
        }
        h.raw("</tr></thead><tbody>");
        for (name, tenant, _) in &listing {
            let runners = (policy.runners.iter())
                .filter(|r| r.tenant == **name && r.gitlab == gitlab)
                .map(|r| format!("{} ({})", r.runner_id, r.class))
                .collect::<Vec<_>>();
            h.raw("<tr><td><a href=\"")
                .text(tenant_path(name))
                .raw("\">")
                .text(name)
                .raw("</a></td><td class=\"num\">")
                .text(tenant.weight)
                .raw("</td><td>")
                .text(cap(tenant))
                .raw("</td><td>")
                .text(if runners.is_empty() {
                    "none".to_owned()
                } else {
                    runners.join(", ")
                })
                .raw("</td>");
            if steer {
                h.raw("<td class=\"actions\">");
                button_form(
                    h,
                    auth,
                    REMOVE_PROJECT,
                    &digest,
                    &project_fields(name),
                    "Remove",
                );
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    if steer {
        let others: Vec<_> = (policy.tenants.keys())
            .filter(|name| policy.project(name, gitlab, id).is_none())
            .collect();
        if !others.is_empty() {
            edit_form(h, auth, ADD_PROJECT, &digest);
            hidden(h, "gitlab", gitlab);
            hidden(h, "project", id);
            hidden(h, "from", FROM_PROJECT);
            h.raw("<label>Tenant <select name=\"tenant\">");
            for name in others {
                h.raw("<option>").text(name).raw("</option>");
            }
            h.raw("</select></label><button>List it for this tenant</button></form>");
        }
    }
    let Some((first, _, project)) = listing.first() else {
        h.raw("</section>");
        return Ok(());
    };
    if listing.len() > 1 {
        h.raw("<p class=\"sub\">Its production branches and placement rules apply in every ")
            .raw("tenant listed above.</p>");
    }
    h.raw("<h3>Production branches</h3><p class=\"sub\">Globs, one per line: <code>*</code> ")
        .raw("matches within a <code>/</code>-separated part, <code>**</code> across them. A ")
        .raw("production runner's job must be a pipeline of a branch one matches, as its ")
        .raw("sources show it; a tag or merge request pipeline never is.</p>");
    if steer {
        edit_form(h, auth, SET_BRANCHES, &digest);
        hidden(h, "tenant", first);
        hidden(h, "gitlab", gitlab);
        hidden(h, "project", id);
        h.raw("<textarea name=\"branches\" rows=\"4\" spellcheck=\"false\" ")
            .raw("aria-label=\"Production branches\" placeholder=\"main&#10;release/**\">")
            .text(project.production_branches.join("\n"))
            .raw("</textarea><button>Save branches</button></form>");
    } else if project.production_branches.is_empty() {
        h.raw("<p class=\"empty\">None: its production runners take none of its jobs.</p>");
    } else {
        h.raw("<pre>")
            .text(project.production_branches.join("\n"))
            .raw("</pre>");
    }
    h.raw("<h3>Placement rules</h3>");
    placement_help(h);
    if project.placement_rules.is_empty() {
        h.raw("<p class=\"empty\">None: its jobs may go to any node.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>jobs</th><th>nodes</th><th>pools</th>");
        if steer {
            h.raw("<th></th>");
        }
        h.raw("</tr></thead><tbody>");
        for (i, rule) in project.placement_rules.iter().enumerate() {
            h.raw("<tr><td>");
            if rule.branches.is_empty() {
                h.raw("every job");
            } else {
                h.raw("refs matching <code>")
                    .text(rule.branches.join(", "))
                    .raw("</code>");
            }
            for list in [&rule.nodes, &rule.pools] {
                h.raw("</td><td>");
                if list.is_empty() {
                    h.raw("<span class=\"sub\">any</span>");
                } else {
                    h.raw("<code>").text(list.join(", ")).raw("</code>");
                }
            }
            h.raw("</td>");
            if steer {
                let fields = [
                    ("tenant", first.to_string()),
                    ("gitlab", gitlab.to_owned()),
                    ("project", id.to_string()),
                    ("index", i.to_string()),
                ];
                h.raw("<td class=\"actions\">");
                button_form(h, auth, REMOVE_RULE, &digest, &fields, "Remove");
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    if steer {
        h.raw("<h4>Add a rule</h4>");
        edit_form(h, auth, ADD_RULE, &digest);
        hidden(h, "tenant", first);
        hidden(h, "gitlab", gitlab);
        hidden(h, "project", id);
        h.raw("<label>Refs, one glob per line, none for every job<textarea name=\"branches\" ")
            .raw("rows=\"3\" spellcheck=\"false\"></textarea></label>")
            .raw("<label>Node IDs, one per line, none for any<textarea name=\"nodes\" ")
            .raw("rows=\"3\" spellcheck=\"false\"></textarea></label>")
            .raw("<label>Pools, one per line, none for any<textarea name=\"pools\" ")
            .raw("rows=\"3\" spellcheck=\"false\"></textarea></label>")
            .raw("<button>Add rule</button></form>");
    }
    h.raw("</section>");
    Ok(())
}

/// What placement rules do, beside their editor.
fn placement_help(h: &mut Html) {
    h.raw("<p class=\"sub\">A job goes only to a node every rule that applies to it allows: ")
        .raw("one of its nodes and in one of its pools, either any when empty but not both. A ")
        .raw("rule applies to every job, or with refs (globs) to jobs whose ref matches one, ")
        .raw("branch, tag or merge request alike, as the relay reports it; every rule applies ")
        .raw("to a job whose ref is unknown. That ref is no trust boundary: a fork's merge ")
        .raw("request from a branch named <code>main</code> gets <code>main</code>'s rules. To ")
        .raw("confine every job of the project, use a rule without refs. A job no allowed node ")
        .raw("takes waits, and ends at its placement deadline.</p>");
}

/// `POST /capacity`: an edit of the policy, as the operator session's principal.
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
    // A browser posts a textarea's line breaks as CRLF, and the question's hidden fields'
    // as it pleases: compare them as LF.
    let form: Vec<(String, String)> = form
        .into_iter()
        .map(|(k, v)| (k, v.replace("\r\n", "\n")))
        .collect();
    let (op, fields, back) = match edit(&form) {
        Ok(edit) => edit,
        Err(why) => return Ok(refused_page(&auth, PATH, StatusCode::BAD_REQUEST, why)),
    };
    // A field a form leaves out is empty, as the question's form posts it.
    let mut form = form;
    for &name in fields {
        if field(&form, name).is_none() {
            form.push((name.to_owned(), String::new()));
        }
    }
    if op == ADD_TENANT {
        let name = field(&form, "tenant").unwrap_or("").to_owned();
        let (hub, actor, added) = (ui.hub.clone(), auth.session.principal(), name.clone());
        let result =
            blocking(move || add_tenant(&hub.db, || hub.db.capacity_policy(), &added, &actor))
                .await?;
        return Ok(match result {
            Ok(changed) => {
                if changed {
                    ui.hub.touch();
                    ui.hub.clients_changed();
                }
                super::clients::see_other(&tenant_path(&name))
            }
            Err((status, why)) => refused_page(&auth, &back, status, &why),
        });
    }
    let hub = ui.hub.clone();
    let current = match blocking(move || Ok(hub.db.capacity_policy())).await? {
        Ok(current) => current,
        Err(e) => {
            let why = format!("{e:#}");
            return Ok(refused_page(&auth, &back, StatusCode::CONFLICT, &why));
        }
    };
    let expected = field(&form, "expected").unwrap_or("").to_owned();
    if expected != current.digest()? {
        return Ok(refused_page(&auth, &back, StatusCode::CONFLICT, STALE));
    }
    let proposed = match propose(&current, &form, op).and_then(|p| p.validate().map(|()| p)) {
        Ok(proposed) => proposed,
        Err(e) => {
            let why = format!("{e:#}");
            return Ok(refused_page(&auth, &back, StatusCode::BAD_REQUEST, &why));
        }
    };
    // Unlike the store, ignore reordered runner mappings: such an edit is not saved.
    if policy_changes(&current, &proposed).is_empty() {
        return Ok(super::clients::see_other(&back));
    }
    let mut detail = Html::new();
    detail.raw("<ul>");
    for change in describe(&current, &proposed) {
        detail.raw("<li>").text(change).raw("</li>");
    }
    detail.raw("</ul>");
    let ask = actions::Ask {
        path: PATH.to_owned(),
        back: back.clone(),
        op: op.to_owned(),
        what: "Change the capacity policy? Jobs it no longer allows wait or are refused.",
        detail,
        asked: (fields.iter())
            .map(|&name| (name, field(&form, name).unwrap_or("").to_owned()))
            .collect(),
    };
    if let Some(response) =
        actions::ask_first(&site.questions, fleet::layout, htmx, &auth, &form, &ask)?
    {
        return Ok(response);
    }
    let unlisted = (op == REMOVE_PROJECT && field(&form, "from") == Some(FROM_PROJECT))
        .then(|| target(&form, "project"))
        .flatten()
        .filter(|(gitlab, id)| proposed.project_any(gitlab, *id).is_none());
    let (hub, actor) = (ui.hub.clone(), auth.session.principal());
    let result = blocking(move || {
        Ok(hub
            .db
            .replace_capacity_policy_if(&proposed, &expected, &actor, crate::now_secs()))
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
            return Ok(refused_page(&auth, &back, status, &why));
        }
    }
    // A project the hub has not seen has a page only while the policy lists it: once no
    // tenant does, lead back to the tenant's page instead.
    if let Some((gitlab, id)) = unlisted {
        let hub = ui.hub.clone();
        if blocking(move || hub.db.gitlab_project(&gitlab, id))
            .await?
            .is_none()
        {
            let tenant = field(&form, "tenant").unwrap_or("");
            return Ok(super::clients::see_other(&tenant_path(tenant)));
        }
    }
    Ok(super::clients::see_other(&back))
}

/// Add tenant `name`, with weight 1 and no projects or runners, to the policy `read` returns,
/// as `actor`. Preserve concurrent edits by rereading once if another edit stores first.
/// Return whether the policy changed, or the refusal's status and reason.
fn add_tenant(
    db: &crate::store::Db,
    read: impl Fn() -> Result<Policy>,
    name: &str,
    actor: &str,
) -> Result<Result<bool, (StatusCode, String)>> {
    if !crate::store::valid_name(name) {
        return Ok(Err((
            StatusCode::BAD_REQUEST,
            "not a valid tenant name".into(),
        )));
    }
    for _ in 0..2 {
        let current = match read() {
            Ok(current) => current,
            Err(e) => return Ok(Err((StatusCode::CONFLICT, format!("{e:#}")))),
        };
        if current.tenant(name).is_some() {
            let why = format!("tenant {name:?} exists already");
            return Ok(Err((StatusCode::BAD_REQUEST, why)));
        }
        let tenant = Tenant {
            weight: 1,
            cap: None,
            projects: Vec::new(),
        };
        let mut proposed = current.clone();
        proposed.tenants.insert(name.to_owned(), tenant);
        match db.replace_capacity_policy_if(&proposed, &current.digest()?, actor, crate::now_secs())
        {
            Ok(changed) => return Ok(Ok(changed)),
            Err(e) => match e.downcast_ref::<PolicyRefused>() {
                Some(PolicyRefused::Conflict) => {}
                Some(refusal) => return Ok(Err((StatusCode::BAD_REQUEST, refusal.to_string()))),
                None => return Err(e),
            },
        }
    }
    let why = "the capacity policy kept changing; retry";
    Ok(Err((StatusCode::CONFLICT, why.into())))
}

/// The instance and ID `form` names in `name`: `<instance>/<ID>`, as a picker posts it, or an
/// ID beside an instance in `gitlab`. Only names and positive IDs.
fn target(form: &[(String, String)], name: &str) -> Option<(String, u64)> {
    let value = field(form, name)?;
    let (gitlab, id) = match value.split_once('/') {
        Some((gitlab, id)) => (gitlab, id),
        None => (field(form, "gitlab")?, value),
    };
    let id = id.trim().parse::<u64>().ok().filter(|&id| id > 0)?;
    crate::store::valid_gitlab_name(gitlab).then(|| (gitlab.to_owned(), id))
}

/// The requested op, fields confirmation must preserve, and source page built from checked
/// names; otherwise, the refusal reason.
fn edit(
    form: &[(String, String)],
) -> Result<(&'static str, &'static [&'static str], String), &'static str> {
    const INVALID: &str = "invalid project or tenant";
    let tenant = || {
        field(form, "tenant")
            .filter(|t| crate::store::valid_name(t))
            .ok_or(INVALID)
    };
    let project = || -> Result<String, &'static str> {
        tenant()?;
        let (gitlab, id) = target(form, "project").ok_or(INVALID)?;
        Ok(super::projects::path(&gitlab, id))
    };
    let op = field(form, "op").unwrap_or("");
    let (op, fields, back): (_, &'static [&'static str], _) = match op {
        SET_POLICY => (SET_POLICY, &["expected", "policy"], PATH.to_owned()),
        ADD_TENANT => (ADD_TENANT, &["tenant"], PATH.to_owned()),
        REMOVE_TENANT => {
            tenant()?;
            (REMOVE_TENANT, &["expected", "tenant"], PATH.to_owned())
        }
        SET_SHARE => (
            SET_SHARE,
            &["expected", "tenant", "weight", "cap"],
            tenant_path(tenant()?),
        ),
        ADD_PROJECT | REMOVE_PROJECT => {
            let back = if field(form, "from") == Some(FROM_PROJECT) {
                project()?
            } else {
                project()?;
                tenant_path(tenant()?)
            };
            let op = if op == ADD_PROJECT {
                ADD_PROJECT
            } else {
                REMOVE_PROJECT
            };
            (
                op,
                &["expected", "tenant", "gitlab", "project", "from"],
                back,
            )
        }
        MAP_RUNNER | UNMAP_RUNNER => {
            target(form, "runner").ok_or("invalid runner")?;
            let back = tenant_path(tenant()?);
            if op == MAP_RUNNER {
                let fields = &["expected", "tenant", "gitlab", "runner", "class"];
                (MAP_RUNNER, fields, back)
            } else {
                (
                    UNMAP_RUNNER,
                    &["expected", "tenant", "gitlab", "runner"],
                    back,
                )
            }
        }
        SET_FALLBACK => (SET_FALLBACK, &["expected", "tenant"], PATH.to_owned()),
        SET_CLIENT => (
            SET_CLIENT,
            &["expected", "principal", "tenant"],
            PATH.to_owned(),
        ),
        SET_SCHEDULING => (
            SET_SCHEDULING,
            &[
                "expected",
                "probe_limit",
                "production_probe_burst",
                "backoff_initial_secs",
                "backoff_max_secs",
                "busy_secs",
            ],
            PATH.to_owned(),
        ),
        ADD_HEADROOM => (
            ADD_HEADROOM,
            &[
                "expected", "pool", "labels", "slots", "mem_mib", "cpus", "disk_gib",
            ],
            PATH.to_owned(),
        ),
        REMOVE_HEADROOM => (REMOVE_HEADROOM, &["expected", "index"], PATH.to_owned()),
        SET_BRANCHES => (
            SET_BRANCHES,
            &["expected", "tenant", "gitlab", "project", "branches"],
            project()?,
        ),
        ADD_RULE => (
            ADD_RULE,
            &[
                "expected", "tenant", "gitlab", "project", "branches", "nodes", "pools",
            ],
            project()?,
        ),
        REMOVE_RULE => (
            REMOVE_RULE,
            &["expected", "tenant", "gitlab", "project", "index"],
            project()?,
        ),
        _ => return Err("no such edit"),
    };
    Ok((op, fields, back))
}

/// Trim `value`'s lines and omit empty ones.
fn lines(value: &str) -> Vec<String> {
    (value.lines())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parse `value` as a number; name `what` in the error.
fn number<T: std::str::FromStr>(value: &str, what: &str) -> Result<T> {
    (value.trim().parse().ok()).with_context(|| format!("{what} must be a whole number"))
}

/// The policy `op` makes of `current` with `form`'s fields, not yet validated.
fn propose(current: &Policy, form: &[(String, String)], op: &str) -> Result<Policy> {
    let value = |name| field(form, name).unwrap_or("");
    let tenant = value("tenant");
    let no_tenant = || anyhow::anyhow!("no tenant {tenant:?}");
    let project = || target(form, "project").context("invalid project");
    let runner = || target(form, "runner").context("invalid runner");
    let mut policy = current.clone();
    match op {
        SET_POLICY => {
            return serde_json::from_str(value("policy")).context("not a capacity policy");
        }
        REMOVE_TENANT => {
            if current.fallback == tenant {
                bail!("tenant {tenant:?} is the fallback: make another the fallback first");
            }
            policy.tenants.remove(tenant).ok_or_else(no_tenant)?;
            policy.runners.retain(|r| r.tenant != tenant);
            policy.clients.retain(|_, t| t != tenant);
        }
        SET_SHARE => {
            let t = policy.tenants.get_mut(tenant).ok_or_else(no_tenant)?;
            t.weight = number(value("weight"), "the weight")?;
            t.cap = match value("cap").trim() {
                "" => None,
                cap => Some(number(cap, "the cap")?),
            };
        }
        ADD_PROJECT => {
            let (gitlab, id) = project()?;
            // A project other tenants list keeps its branches and rules.
            let listed = current.project_any(&gitlab, id).cloned();
            let t = policy.tenants.get_mut(tenant).ok_or_else(no_tenant)?;
            if t.projects.iter().any(|p| p.gitlab == gitlab && p.id == id) {
                bail!("tenant {tenant:?} lists project {gitlab}/{id} already");
            }
            t.projects.push(listed.unwrap_or(Project {
                gitlab,
                id,
                production_branches: Vec::new(),
                placement_rules: Vec::new(),
            }));
        }
        REMOVE_PROJECT => {
            let (gitlab, id) = project()?;
            let t = policy.tenants.get_mut(tenant).ok_or_else(no_tenant)?;
            let before = t.projects.len();
            t.projects.retain(|p| !(p.gitlab == gitlab && p.id == id));
            if t.projects.len() == before {
                bail!("tenant {tenant:?} does not list project {gitlab}/{id}");
            }
        }
        MAP_RUNNER => {
            let (gitlab, runner_id) = runner()?;
            let class = match value("class") {
                "normal" => Class::Normal,
                "production" => Class::Production,
                _ => bail!("a runner's class is normal or production"),
            };
            current.tenant(tenant).ok_or_else(no_tenant)?;
            let mapping = RunnerMapping {
                gitlab,
                runner_id,
                tenant: tenant.to_owned(),
                class,
            };
            match (policy.runners.iter_mut())
                .find(|r| r.gitlab == mapping.gitlab && r.runner_id == runner_id)
            {
                Some(r) => *r = mapping,
                None => policy.runners.push(mapping),
            }
        }
        UNMAP_RUNNER => {
            let (gitlab, runner_id) = runner()?;
            let before = policy.runners.len();
            (policy.runners).retain(|r| {
                !(r.gitlab == gitlab && r.runner_id == runner_id && r.tenant == tenant)
            });
            if policy.runners.len() == before {
                bail!("runner {gitlab}/{runner_id} is not mapped to tenant {tenant:?}");
            }
        }
        SET_FALLBACK => {
            current.tenant(tenant).ok_or_else(no_tenant)?;
            policy.fallback = tenant.to_owned();
        }
        SET_CLIENT => {
            let principal = value("principal").trim();
            if principal.is_empty() {
                bail!("no API client principal ID");
            }
            if tenant.is_empty() {
                policy.clients.remove(principal);
            } else {
                current.tenant(tenant).ok_or_else(no_tenant)?;
                (policy.clients).insert(principal.to_owned(), tenant.to_owned());
            }
        }
        SET_SCHEDULING => {
            policy.probe_limit = number(value("probe_limit"), "the probe limit")?;
            policy.production_probe_burst = number(
                value("production_probe_burst"),
                "the production probe burst",
            )?;
            policy.backoff_initial_secs =
                number(value("backoff_initial_secs"), "the initial backoff")?;
            policy.backoff_max_secs = number(value("backoff_max_secs"), "the maximum backoff")?;
            policy.busy_secs = number(value("busy_secs"), "the busy time")?;
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
            // Placement matches labels as a set: so does an entry kept already.
            fn labels(h: &Headroom) -> BTreeSet<&String> {
                h.placement.labels.iter().collect()
            }
            if (policy.headroom.iter()).any(|h| {
                h.slots == headroom.slots
                    && h.placement.pool == headroom.placement.pool
                    && h.placement.envelope == headroom.placement.envelope
                    && labels(h) == labels(&headroom)
            }) {
                bail!("the policy keeps this headroom already");
            }
            policy.headroom.push(headroom);
        }
        REMOVE_HEADROOM => {
            let index: usize = number(value("index"), "the headroom entry")?;
            if index >= policy.headroom.len() {
                bail!("no such headroom entry");
            }
            policy.headroom.remove(index);
        }
        SET_BRANCHES => {
            let (gitlab, id) = project()?;
            let branches = lines(value("branches"));
            return current.with_project(tenant, &gitlab, id, |p| {
                p.production_branches.clone_from(&branches);
            });
        }
        ADD_RULE => {
            let (gitlab, id) = project()?;
            let rule = PlacementRule {
                branches: lines(value("branches")),
                nodes: lines(value("nodes")),
                pools: lines(value("pools")),
            };
            if rule.nodes.is_empty() && rule.pools.is_empty() {
                bail!("a placement rule names some nodes or pools");
            }
            let listed = current.project(tenant, &gitlab, id);
            if listed.is_some_and(|p| p.placement_rules.iter().any(|r| r.same_as(&rule))) {
                bail!("the project has this rule already");
            }
            return current.with_project(tenant, &gitlab, id, |p| {
                p.placement_rules.push(rule.clone());
            });
        }
        REMOVE_RULE => {
            let (gitlab, id) = project()?;
            let index: usize = number(value("index"), "the rule")?;
            let rule = (current.project(tenant, &gitlab, id))
                .and_then(|p| p.placement_rules.get(index))
                .cloned()
                .context("no such placement rule")?;
            // Other tenants may list the same rules in another order.
            return current.with_project(tenant, &gitlab, id, |p| {
                p.placement_rules.retain(|r| !r.same_as(&rule));
            });
        }
        _ => bail!("no such edit"),
    }
    Ok(policy)
}

/// What changes from `before` to `after`, a line each, as a question lists it: at most
/// [`MAX_DESCRIBED`], the rest counted.
fn describe(before: &Policy, after: &Policy) -> Vec<String> {
    let mut out = Vec::new();
    let names: BTreeSet<_> = before.tenants.keys().chain(after.tenants.keys()).collect();
    for name in names {
        match (before.tenants.get(name), after.tenants.get(name)) {
            (None, Some(t)) => {
                out.push(format!(
                    "Add tenant {name}, of weight {} and cap {}",
                    t.weight,
                    cap(t)
                ));
                for p in &t.projects {
                    out.push(format!("Tenant {name}: list project {}/{}", p.gitlab, p.id));
                }
            }
            (Some(_), None) => out.push(format!("Remove tenant {name}")),
            (Some(b), Some(a)) => {
                if b.weight != a.weight {
                    out.push(format!("Tenant {name}: weight {} → {}", b.weight, a.weight));
                }
                if b.cap != a.cap {
                    out.push(format!("Tenant {name}: cap {} → {}", cap(b), cap(a)));
                }
                let keys = |t: &Tenant| -> BTreeSet<(String, u64)> {
                    t.projects
                        .iter()
                        .map(|p| (p.gitlab.clone(), p.id))
                        .collect()
                };
                let (kb, ka) = (keys(b), keys(a));
                for (gitlab, id) in ka.difference(&kb) {
                    out.push(format!("Tenant {name}: list project {gitlab}/{id}"));
                }
                for (gitlab, id) in kb.difference(&ka) {
                    out.push(format!("Tenant {name}: stop listing project {gitlab}/{id}"));
                }
            }
            (None, None) => {}
        }
    }
    let projects: BTreeSet<_> = (before.tenants.values().chain(after.tenants.values()))
        .flat_map(|t| &t.projects)
        .map(|p| (p.gitlab.as_str(), p.id))
        .collect();
    for (gitlab, id) in projects {
        // A project newly listed is described against no branches and no rules.
        let empty = Project {
            gitlab: gitlab.to_owned(),
            id,
            production_branches: Vec::new(),
            placement_rules: Vec::new(),
        };
        let Some(a) = after.project_any(gitlab, id) else {
            continue;
        };
        let b = before.project_any(gitlab, id).unwrap_or(&empty);
        if b.production_branches != a.production_branches {
            out.push(format!(
                "Project {gitlab}/{id}: production branches {} → {}",
                list_text(&b.production_branches),
                list_text(&a.production_branches)
            ));
        }
        if !crate::policy::same_rules(&b.placement_rules, &a.placement_rules) {
            let has =
                |rules: &[PlacementRule], r: &PlacementRule| rules.iter().any(|o| o.same_as(r));
            for r in a
                .placement_rules
                .iter()
                .filter(|r| !has(&b.placement_rules, r))
            {
                out.push(format!(
                    "Project {gitlab}/{id}: add placement rule {}",
                    rule_text(r)
                ));
            }
            for r in b
                .placement_rules
                .iter()
                .filter(|r| !has(&a.placement_rules, r))
            {
                out.push(format!(
                    "Project {gitlab}/{id}: remove placement rule {}",
                    rule_text(r)
                ));
            }
        }
    }
    let by_key = |p: &Policy| -> BTreeMap<(String, u64), RunnerMapping> {
        (p.runners.iter())
            .map(|r| ((r.gitlab.clone(), r.runner_id), r.clone()))
            .collect()
    };
    let (rb, ra) = (by_key(before), by_key(after));
    let keys: BTreeSet<_> = rb.keys().chain(ra.keys()).collect();
    for key @ (gitlab, id) in keys {
        match (rb.get(key), ra.get(key)) {
            (None, Some(a)) => out.push(format!(
                "Runner {gitlab}/{id}: map to tenant {} as {}",
                a.tenant, a.class
            )),
            (Some(b), None) => out.push(format!(
                "Runner {gitlab}/{id}: unmap from tenant {}; it gets no work",
                b.tenant
            )),
            (Some(b), Some(a)) if b != a => out.push(format!(
                "Runner {gitlab}/{id}: tenant {} as {} → tenant {} as {}",
                b.tenant, b.class, a.tenant, a.class
            )),
            _ => {}
        }
    }
    let principals: BTreeSet<_> = before.clients.keys().chain(after.clients.keys()).collect();
    for principal in principals {
        let tenant = |p: &Policy| match p.clients.get(principal) {
            Some(t) => t.clone(),
            None => format!("the fallback ({})", p.fallback),
        };
        if before.clients.get(principal) != after.clients.get(principal) {
            out.push(format!(
                "API client {principal}: {} → {}",
                tenant(before),
                tenant(after)
            ));
        }
    }
    if before.fallback != after.fallback {
        out.push(format!(
            "Fallback tenant: {} → {}",
            before.fallback, after.fallback
        ));
    }
    for (what, b, a) in [
        ("Busy time", before.busy_secs, after.busy_secs),
        (
            "Probe limit",
            before.probe_limit.into(),
            after.probe_limit.into(),
        ),
        (
            "Production probe burst",
            before.production_probe_burst.into(),
            after.production_probe_burst.into(),
        ),
        (
            "Initial backoff",
            before.backoff_initial_secs,
            after.backoff_initial_secs,
        ),
        (
            "Maximum backoff",
            before.backoff_max_secs,
            after.backoff_max_secs,
        ),
    ] {
        if b != a {
            out.push(format!("{what}: {b} → {a}"));
        }
    }
    let has = |list: &[Headroom], h: &Headroom| list.contains(h);
    for h in after.headroom.iter().filter(|h| !has(&before.headroom, h)) {
        out.push(format!("Keep headroom: {}", headroom_text(h)));
    }
    for h in before.headroom.iter().filter(|h| !has(&after.headroom, h)) {
        out.push(format!("Stop keeping headroom: {}", headroom_text(h)));
    }
    if out.len() > MAX_DESCRIBED {
        let more = out.len() - MAX_DESCRIBED;
        out.truncate(MAX_DESCRIBED);
        out.push(format!("and {more} more changes"));
    }
    if out.is_empty() {
        // Only an order changed, or a duplicate rule or headroom entry (JSON editor) came or
        // went.
        out = policy_changes(before, after);
    }
    out
}

fn list_text(list: &[String]) -> String {
    if list.is_empty() {
        "none".to_owned()
    } else {
        list.join(", ")
    }
}

fn rule_text(r: &PlacementRule) -> String {
    let jobs = if r.branches.is_empty() {
        "every job".to_owned()
    } else {
        format!("refs {}", r.branches.join(", "))
    };
    let any = |list: &[String]| {
        if list.is_empty() {
            "any".to_owned()
        } else {
            list.join(", ")
        }
    };
    format!("({jobs}: nodes {}, pools {})", any(&r.nodes), any(&r.pools))
}

fn headroom_text(h: &Headroom) -> String {
    let p = &h.placement;
    let labels = if p.labels.is_empty() {
        String::new()
    } else {
        format!(" [{}]", p.labels.join(", "))
    };
    let e = p.envelope;
    // Exact, where `envelope_text` rounds the disk down to GiB.
    let disk = if e.disk_bytes.is_multiple_of(1 << 30) {
        format!("{} GiB", e.disk_bytes >> 30)
    } else {
        format!("{} bytes", e.disk_bytes)
    };
    format!(
        "{} × {} MiB, {} CPUs, {disk} disk in pool {}{labels}",
        h.slots, e.mem_mib, e.cpus, p.pool
    )
}

/// An edit refused for `why`, as a page leading back to `back`, a hub path.
fn refused_page(auth: &Auth, back: &str, status: StatusCode, why: &str) -> Response<Body> {
    let mut main = Html::new();
    main.raw("<p class=\"message\">")
        .text(format!("Refused: {}.", why.trim_end_matches('.')))
        .raw("</p><p><a href=\"")
        .text(back)
        .raw("\">Back</a></p>");
    let mut resp = page(fleet::layout("Capacity policy", back, auth, &main));
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// A question names a new tenant's projects with their settings, and headroom exactly.
    #[test]
    fn new_tenants_projects_and_headroom_are_described_in_full() {
        let before = Policy::default();
        let mut after = before.clone();
        let project = Project {
            gitlab: "gl".into(),
            id: 42,
            production_branches: vec!["main".into()],
            placement_rules: vec![PlacementRule {
                branches: vec![],
                nodes: vec![],
                pools: vec!["trusted".into()],
            }],
        };
        let tenant = Tenant {
            weight: 2,
            cap: None,
            projects: vec![project],
        };
        after.tenants.insert("ci".into(), tenant);
        after.headroom.push(Headroom {
            placement: Placement {
                pool: "ci".into(),
                labels: vec![],
                envelope: Envelope {
                    mem_mib: 512,
                    cpus: 1,
                    disk_bytes: 3 << 29,
                },
            },
            slots: 1,
        });
        assert_eq!(
            describe(&before, &after),
            [
                "Add tenant ci, of weight 2 and cap unbounded",
                "Tenant ci: list project gl/42",
                "Project gl/42: production branches none → main",
                "Project gl/42: add placement rule (every job: nodes any, pools trusted)",
                "Keep headroom: 1 × 512 MiB, 1 CPUs, 1610612736 bytes disk in pool ci",
            ]
        );
    }

    /// Adding a tenant retries once after a concurrent edit; a second conflict is refused.
    #[test]
    fn adding_a_tenant_reads_the_policy_again_once() {
        let db = crate::store::Db::open_memory().unwrap();
        let edits = Cell::new(0);
        // Read the policy, then store another edit.
        let racing = || {
            let read = db.capacity_policy();
            let mut other = db.capacity_policy().unwrap();
            edits.set(edits.get() + 1);
            other.probe_limit = 1 + edits.get();
            db.set_capacity_policy(&other, "u", 0).unwrap();
            read
        };
        let reads = Cell::new(0);
        let once = || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                racing()
            } else {
                db.capacity_policy()
            }
        };
        assert_eq!(add_tenant(&db, once, "web", "u").unwrap(), Ok(true));
        assert_eq!(reads.get(), 2);
        let saved = db.capacity_policy().unwrap();
        assert!(saved.tenant("web").is_some());
        assert_eq!(saved.probe_limit, 2);
        assert_eq!(
            add_tenant(&db, racing, "api", "u").unwrap(),
            Err((
                StatusCode::CONFLICT,
                "the capacity policy kept changing; retry".into()
            ))
        );
        assert!(db.capacity_policy().unwrap().tenant("api").is_none());
    }
}
