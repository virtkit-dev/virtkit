//! Capacity policy pages for viewers and operators: the whole policy at [`PATH`], tenants at
//! [`tenant_path`], and each project's share on its page ([`project_section`]). Operators post
//! edits to [`PATH`]: the whole policy in `vk-hub capacity-policy set` format, a tenant with its
//! runner mappings, or a project's production branches and placement rules in every tenant
//! listing it.
//!
//! Adding a tenant uses the current policy and rereads once if another edit stores first.
//! Other edits use the displayed policy and are refused as stale if its digest has changed.
//! Each edit uses the CLI's validation and [`crate::store::Db::replace_capacity_policy_if`],
//! which rechecks the digest and audits changes in the same transaction.
//! All but adding a tenant ask first
//! ([`actions::ask_first`]), listing what would change: any of them may keep jobs from running.

use anyhow::{Context, Result, bail};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, field, message, page};
use crate::policy::{Policy, Tenant};
use crate::store::{PolicyRefused, Role, policy_changes};

/// The whole policy's page, and where its editors post.
pub(super) const PATH: &str = "/clients/capacity";

const TENANTS: &str = "/clients/tenants/";

/// The largest edit posted: a policy the admin socket takes (64 KiB), as a browser posts it.
/// Pretty-printed and urlencoded, with 3 bytes for each `"`, `:`, `,`, brace and bracket and 6
/// for each CRLF, a policy grows about 2.9 times for runner mappings and 4 for nested short
/// branch globs. Each of [`actions`]' questions holds the edit it asks about: up to
/// `MAX_QUESTIONS` (1024) times this, 384 MiB, all of operators.
const MAX_FORM: usize = 6 * 64 * 1024;

/// Replace the whole policy: `expected`, `policy`.
const SET_POLICY: &str = "capacity-policy";
/// Add a tenant of weight 1 with no projects nor runners: `tenant`.
const ADD_TENANT: &str = "capacity-add-tenant";
/// Replace a tenant and its runner mappings: `expected`, `tenant`, `settings`, `runners`.
const SET_TENANT: &str = "capacity-tenant";
/// Set a project's production branches, one per line: `expected`, `tenant`, `gitlab`,
/// `project`, `branches`.
const SET_BRANCHES: &str = "capacity-branches";
/// Set a project's placement rules: `expected`, `tenant`, `gitlab`, `project`, `rules`.
const SET_PLACEMENT: &str = "capacity-placement";

/// Why an edit based on a replaced policy is refused.
const STALE: &str = "the capacity policy changed since this page was shown; reload it and retry";

/// Tenant `name`'s page.
pub(super) fn tenant_path(name: &str) -> String {
    format!("{TENANTS}{name}")
}

/// The tenant named by the page at `path`.
pub(super) fn tenant_target(path: &str) -> Option<&str> {
    let name = path.strip_prefix(TENANTS)?;
    crate::store::valid_name(name).then_some(name)
}

/// What a page says in place of a policy this hub cannot read.
pub(super) fn unreadable(h: &mut Html, error: &anyhow::Error) {
    h.raw("<p class=\"message\">")
        .text(format!("{error:#}"))
        .raw("</p>");
}

/// `GET /clients/capacity`.
pub(super) async fn policy_get(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let policy = blocking(move || Ok(hub.db.capacity_policy())).await?;
    let mut main = Html::new();
    main.raw("<h1>Capacity policy</h1><p>Tenants, their projects and weights, runner ")
        .raw("mappings, API clients, headroom and discovery settings, as ")
        .raw("<code>vk-hub capacity-policy show</code> prints them.");
    match &policy {
        Ok(policy) => {
            main.raw(" Tenants: ");
            for (i, name) in policy.tenants.keys().enumerate() {
                if i > 0 {
                    main.raw(", ");
                }
                main.raw("<a href=\"")
                    .text(tenant_path(name))
                    .raw("\">")
                    .text(name)
                    .raw("</a>");
            }
            main.raw(".</p>");
            let json = serde_json::to_string_pretty(policy)?;
            if auth.session.role >= Role::Operator {
                edit_form(&mut main, auth, SET_POLICY, &policy.digest()?);
                main.raw("<label>Policy (JSON)<textarea name=\"policy\" rows=\"24\">")
                    .text(json)
                    .raw("</textarea></label><button>Save policy</button></form>");
            } else {
                main.raw("<pre>").text(json).raw("</pre>");
            }
        }
        Err(e) => {
            main.raw("</p>");
            unreadable(&mut main, e);
        }
    }
    Ok(page(fleet::layout("Capacity policy", PATH, auth, &main)))
}

/// `GET /clients/tenants/<name>`.
pub(super) async fn tenant_get(name: &str, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let policy = blocking(move || Ok(hub.db.capacity_policy())).await?;
    let mut main = Html::new();
    main.raw("<h1>Tenant ").text(name).raw("</h1>");
    let policy = match policy {
        Ok(policy) => policy,
        Err(e) => {
            unreadable(&mut main, &e);
            return Ok(tenant_page(name, auth, &main));
        }
    };
    let Some(tenant) = policy.tenant(name) else {
        return Ok(message(StatusCode::NOT_FOUND, "No such capacity tenant."));
    };
    pages::section(&mut main, "Share");
    pages::kv(&mut main, "Weight", &tenant.weight.to_string());
    pages::kv(&mut main, "Cap", &cap(tenant));
    if policy.fallback == name {
        pages::kv(&mut main, "Fallback", "API clients assigned no tenant");
    }
    pages::end_section(&mut main);
    main.raw("<section><h2>Projects</h2>");
    if tenant.projects.is_empty() {
        main.raw("<p>None: its runners' jobs are refused.</p>");
    } else {
        main.raw("<ul>");
        for project in &tenant.projects {
            main.raw("<li><a href=\"")
                .text(super::projects::path(&project.gitlab, project.id))
                .raw("\">")
                .text(format!("{} / {}", project.gitlab, project.id))
                .raw("</a></li>");
        }
        main.raw("</ul>");
    }
    main.raw("</section><section><h2>Runners</h2>");
    let runners: Vec<_> = policy.runners.iter().filter(|r| r.tenant == name).collect();
    if runners.is_empty() {
        main.raw("<p>None.</p>");
    } else {
        main.raw("<ul>");
        for runner in &runners {
            main.raw("<li>")
                .text(format!(
                    "{} / {} ({})",
                    runner.gitlab, runner.runner_id, runner.class
                ))
                .raw("</li>");
        }
        main.raw("</ul>");
    }
    main.raw("</section><section><h2>API clients</h2>");
    let clients: Vec<_> = (policy.clients.iter())
        .filter(|(_, t)| *t == name)
        .map(|(principal, _)| principal)
        .collect();
    if clients.is_empty() {
        main.raw("<p>None.</p>");
    } else {
        main.raw("<ul>");
        for principal in clients {
            main.raw("<li><code>").text(principal).raw("</code></li>");
        }
        main.raw("</ul>");
    }
    main.raw("</section>");
    if auth.session.role >= Role::Operator {
        main.raw("<section><h2>Edit</h2>");
        edit_form(&mut main, auth, SET_TENANT, &policy.digest()?);
        main.raw("<input type=\"hidden\" name=\"tenant\" value=\"")
            .text(name)
            .raw("\"><label>Weight, cap and projects (JSON)<textarea name=\"settings\" ")
            .raw("rows=\"12\">")
            .text(serde_json::to_string_pretty(tenant)?)
            .raw("</textarea></label><label>Runner mappings (JSON)<textarea name=\"runners\" ")
            .raw("rows=\"8\">")
            .text(serde_json::to_string_pretty(&runners)?)
            .raw("</textarea></label><p class=\"sub\">A mapping names this tenant; a runner ")
            .raw("mapped to another is moved on the policy's page. A project's branches and ")
            .raw("placement rules must stay the same in every tenant listing it: edit them on ")
            .raw("its page.</p><button>Save tenant</button></form></section>");
    }
    Ok(tenant_page(name, auth, &main))
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
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .raw(op)
        .raw("\"><input type=\"hidden\" name=\"expected\" value=\"")
        .text(expected)
        .raw("\">");
}

/// The form adding a tenant, on Connections.
pub(super) fn add_tenant_form(h: &mut Html, auth: &Auth) {
    h.raw("<section><h2>Add capacity tenant</h2><form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .raw(ADD_TENANT)
        .raw("\"><label>Name <input name=\"tenant\" required></label>")
        .raw("<button>Add</button></form><p class=\"sub\">Of weight 1, with no projects nor ")
        .raw("runners until its page gives it some.</p></section>");
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
    let listing: Vec<_> = (policy.tenants.iter())
        .filter_map(|(name, t)| Some((name, t, policy.project(name, gitlab, id)?)))
        .collect();
    let Some((first, _, project)) = listing.first() else {
        h.raw("<p>No capacity tenant lists it: its relay jobs are refused. List it on a ")
            .raw("tenant's page, from the <a href=\"")
            .raw(PATH)
            .raw("\">capacity policy</a>.</p></section>");
        return Ok(());
    };
    h.raw("<table class=\"grid\"><thead><tr><th>tenant</th><th class=\"num\">weight</th>")
        .raw("<th>cap</th><th>runners</th></tr></thead><tbody>");
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
            .raw("</td></tr>");
    }
    h.raw("</tbody></table><h3>Production branches</h3><p class=\"sub\">Globs: <code>*</code> ")
        .raw("matches within a <code>/</code>-separated part, <code>**</code> across them. A ")
        .raw("production runner's job must be a pipeline of a branch one matches, as its ")
        .raw("sources show it; a tag or merge request pipeline never is.</p>");
    let rules = serde_json::to_string_pretty(&project.placement_rules)?;
    if auth.session.role < Role::Operator {
        h.raw("<pre>")
            .text(project.production_branches.join("\n"))
            .raw("</pre><h3>Placement rules</h3>");
        placement_help(h);
        h.raw("<pre>").text(rules).raw("</pre></section>");
        return Ok(());
    }
    let digest = policy.digest()?;
    let project_fields = |h: &mut Html| {
        h.raw("<input type=\"hidden\" name=\"tenant\" value=\"")
            .text(first)
            .raw("\"><input type=\"hidden\" name=\"gitlab\" value=\"")
            .text(gitlab)
            .raw("\"><input type=\"hidden\" name=\"project\" value=\"")
            .text(id)
            .raw("\">");
    };
    edit_form(h, auth, SET_BRANCHES, &digest);
    project_fields(h);
    h.raw("<label>One per line, trimmed<textarea name=\"branches\" rows=\"4\">")
        .text(project.production_branches.join("\n"))
        .raw("</textarea></label><button>Save branches</button></form><h3>Placement rules</h3>");
    placement_help(h);
    edit_form(h, auth, SET_PLACEMENT, &digest);
    project_fields(h);
    h.raw("<label>Rules (JSON)<textarea name=\"rules\" rows=\"8\">")
        .text(rules)
        .raw("</textarea></label><p class=\"sub\">For example <code>[{\"pools\": [\"trusted\"]}, ")
        .raw("{\"branches\": [\"main\"], \"nodes\": [\"0123456789abcdef0123456789abcdef\"]}]")
        .raw("</code>.</p><button>Save placement rules</button></form></section>");
    Ok(())
}

/// What placement rules do, beside their editor.
fn placement_help(h: &mut Html) {
    h.raw("<p class=\"sub\">A job goes only to a node every rule that applies to it allows: ")
        .raw("one of its <code>nodes</code> (node IDs) and in one of its <code>pools</code>, ")
        .raw("either any when empty but not both. A rule applies to every job, or with ")
        .raw("<code>branches</code> (globs) to jobs whose ref matches one, branch, tag or merge ")
        .raw("request alike, as the relay reports it; every rule applies to a job whose ref is ")
        .raw("unknown. That ref is no trust boundary: a fork's merge request from a branch named ")
        .raw("<code>main</code> gets <code>main</code>'s rules. To confine every job of the ")
        .raw("project, use a rule without branches. A job no allowed node takes waits, and ends ")
        .raw("at its placement deadline.</p>");
}

/// `POST /clients/capacity`: an edit of the policy, as the operator session's principal.
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
    let changes = policy_changes(&current, &proposed);
    // Unlike the store, ignore reordered runner mappings: such an edit is not saved.
    if changes.is_empty() {
        return Ok(super::clients::see_other(&back));
    }
    let mut detail = Html::new();
    detail.raw("<ul>");
    for change in &changes {
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
        let proposed = match current.with_tenant(name, tenant, Vec::new()) {
            Ok(proposed) => proposed,
            Err(e) => return Ok(Err((StatusCode::BAD_REQUEST, format!("{e:#}")))),
        };
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

/// The requested op, fields confirmation must preserve, and source page built from checked
/// names; otherwise, the refusal reason.
fn edit(
    form: &[(String, String)],
) -> Result<(&'static str, &'static [&'static str], String), &'static str> {
    const INVALID: &str = "invalid project or tenant";
    let project = || {
        let gitlab = field(form, "gitlab").filter(|g| crate::store::valid_gitlab_name(g));
        let id = field(form, "project")
            .and_then(|id| id.parse::<u64>().ok())
            .filter(|&id| id > 0);
        let tenant = field(form, "tenant").filter(|t| crate::store::valid_name(t));
        match (gitlab, id, tenant) {
            (Some(gitlab), Some(id), Some(_)) => Ok(super::projects::path(gitlab, id)),
            _ => Err(INVALID),
        }
    };
    match field(form, "op").unwrap_or("") {
        SET_POLICY => Ok((SET_POLICY, &["expected", "policy"], PATH.to_owned())),
        ADD_TENANT => Ok((ADD_TENANT, &["tenant"], super::clients::PATH.to_owned())),
        SET_TENANT => {
            let name = field(form, "tenant").filter(|t| crate::store::valid_name(t));
            let fields = &["expected", "tenant", "settings", "runners"];
            Ok((SET_TENANT, fields, tenant_path(name.ok_or(INVALID)?)))
        }
        SET_BRANCHES => {
            let fields = &["expected", "tenant", "gitlab", "project", "branches"];
            Ok((SET_BRANCHES, fields, project()?))
        }
        SET_PLACEMENT => {
            let fields = &["expected", "tenant", "gitlab", "project", "rules"];
            Ok((SET_PLACEMENT, fields, project()?))
        }
        _ => Err("no such edit"),
    }
}

/// The policy `op` makes of `current` with `form`'s fields, not yet validated.
fn propose(current: &Policy, form: &[(String, String)], op: &str) -> Result<Policy> {
    let value = |name| field(form, name).unwrap_or("");
    let project = || -> Result<(&str, u64)> { Ok((value("gitlab"), value("project").parse()?)) };
    match op {
        SET_POLICY => serde_json::from_str(value("policy")).context("not a capacity policy"),
        SET_TENANT => {
            let name = value("tenant");
            if current.tenant(name).is_none() {
                bail!("no tenant {name:?}");
            }
            let tenant =
                serde_json::from_str(value("settings")).context("not a tenant's settings")?;
            let runners =
                serde_json::from_str(value("runners")).context("not a list of runner mappings")?;
            current.with_tenant(name, tenant, runners)
        }
        SET_BRANCHES => {
            let (gitlab, id) = project()?;
            let branches: Vec<String> = (value("branches").lines())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            current.with_project(value("tenant"), gitlab, id, |p| {
                p.production_branches.clone_from(&branches);
            })
        }
        SET_PLACEMENT => {
            let (gitlab, id) = project()?;
            let rules: Vec<crate::policy::PlacementRule> =
                serde_json::from_str(value("rules")).context("not a list of placement rules")?;
            current.with_project(value("tenant"), gitlab, id, |p| {
                p.placement_rules.clone_from(&rules);
            })
        }
        _ => bail!("no such edit"),
    }
}

/// An edit refused for `why`, as a page leading back to `back`, a hub path.
fn refused_page(auth: &Auth, back: &str, status: StatusCode, why: &str) -> Response<Body> {
    let mut main = Html::new();
    main.raw("<p class=\"message\">")
        .text(format!("Refused: {}.", why.trim_end_matches('.')))
        .raw("</p><p><a href=\"")
        .text(back)
        .raw("\">Back</a></p>");
    let mut resp = page(fleet::layout("Capacity policy", PATH, auth, &main));
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

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
