//! The capacity policy's page at [`PATH`]: its lanes, production headroom and scheduling
//! settings, and, for operators, the whole policy in `vk-hub capacity-policy set` format,
//! replaced against the digest shown ([`crate::store::Db::replace_capacity_policy_if`]) after
//! a question saying what changes ([`actions::ask_first`]). A policy held since its conversion
//! to lanes is activated by setting it again, changed or not. Each project's page lists the
//! lanes that may run it ([`project_section`]).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, field, page};
use crate::policy::{Lane, Policy};
use crate::server::Hub;
use crate::store::{ConversionNote, PolicyRefused, Role, policy_changes};

/// The policy's page, and where its editor posts.
pub(super) const PATH: &str = "/capacity";

/// Pages of the policy's tenants, and the policy's and tenants' pages before the navigation
/// had sections: all lead to [`PATH`].
const OLD_TENANTS: &str = "/capacity/tenants/";
const OLD_PATH: &str = "/clients/capacity";
const OLDER_TENANTS: &str = "/clients/tenants/";

/// The largest edit posted: a policy the admin socket takes (64 KiB), as a browser posts it,
/// pretty-printed and urlencoded.
const MAX_FORM: usize = 6 * 64 * 1024;

/// Replace the whole policy: `policy`.
const SET_POLICY: &str = "capacity-policy";

/// Why an edit based on a replaced policy is refused.
const STALE: &str =
    "the capacity policy changed after this page was shown. Reload the page and try again";

/// The most nodes, or pools, a page lists of a lane; the rest are counted.
const MAX_LISTED_TARGETS: usize = 8;

/// Map a page's `path` from before lanes or navigation sections to its current page.
pub(super) fn moved(path: &str) -> Option<String> {
    (path == OLD_PATH || path.starts_with(OLD_TENANTS) || path.starts_with(OLDER_TENANTS))
        .then(|| PATH.to_string())
}

/// What a page says in place of a policy this hub cannot read.
fn unreadable(h: &mut Html, error: &anyhow::Error) {
    h.raw("<p class=\"message\">")
        .text(format!("{error:#}"))
        .raw("</p>");
}

/// An enrolled node for policy descriptions. Other pages only pass it back to this module.
pub(super) struct KnownNode {
    id: String,
    /// Display-safe hostname, with a short ID for duplicate or missing hostnames.
    label: String,
}

/// The nodes the hub has enrolled, sorted by label. Reads the database: call off the runtime.
pub(super) fn known_nodes(hub: &Hub) -> Result<Vec<KnownNode>> {
    let mut nodes: Vec<_> = (hub.db.nodes()?.into_iter())
        .map(|(id, row)| KnownNode {
            label: vk_hub_proto::display_safe(&row.hostname),
            id,
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

/// Node `id` as `nodes` name it, or as given for a pool or a node the hub has not enrolled.
fn node_label<'a>(nodes: &'a [KnownNode], id: &'a str) -> &'a str {
    (nodes.iter())
        .find(|n| n.id == id)
        .map_or(id, |n| n.label.as_str())
}

/// The nodes `lane` may use, as a page names them.
pub(super) fn may_use_text(lane: &Lane, nodes: &[KnownNode]) -> String {
    let Some(targets) = &lane.nodes else {
        return "any node".to_owned();
    };
    let shown: Vec<_> = (targets.iter())
        .take(MAX_LISTED_TARGETS)
        .map(|t| node_label(nodes, t))
        .collect();
    match targets.len().saturating_sub(MAX_LISTED_TARGETS) {
        0 => shown.join(", "),
        more => format!("{} and {more} more", shown.join(", ")),
    }
}

/// The projects, and their branches, `lane` may run.
fn projects_text(lane: &Lane) -> String {
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
        .map(|p| match &p.branches {
            None => format!("{} · all", p.id),
            Some(b) => format!("{} · {}", p.id, b.join(", ")),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn lane_name(lane: &Lane) -> String {
    lane.id()
        .map_or_else(|| "?".to_owned(), |id| id.to_string())
}

/// What converting the policy to lanes left to review.
fn conversion_section(h: &mut Html, note: &ConversionNote) {
    h.raw("<section><h2>Converted policy</h2>");
    if note.held() {
        h.raw("<p class=\"message\">This policy is proposed, not active: the hub grants no new ")
            .raw("capacity until an operator sets it, changed or not. Running work continues. ")
            .raw("These placement rules do not convert; set the nodes of their lanes:</p><ul>");
        for rule in &note.unconverted {
            h.raw("<li>").text(rule).raw("</li>");
        }
        h.raw("</ul>");
    }
    if !note.shared.is_empty() {
        h.raw("<p class=\"sub\">These lanes each took the whole weight and max slots of a ")
            .raw("tenant they shared: lower them.</p><ul>");
        for (id, tenant) in &note.shared {
            h.raw("<li>")
                .text(id)
                .raw(" (tenant ")
                .text(tenant)
                .raw(")</li>");
        }
        h.raw("</ul>");
    }
    h.raw("</section>");
}

fn lanes_table(h: &mut Html, policy: &Policy, nodes: &[KnownNode]) {
    if policy.lanes.is_empty() {
        h.raw("<p class=\"empty\">No lanes: the hub grants no capacity.</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>lane</th><th>class</th>")
        .raw("<th class=\"num\">weight</th><th>max slots</th><th>nodes</th>")
        .raw("<th>projects · branches</th></tr></thead><tbody>");
    for lane in &policy.lanes {
        h.raw("<tr><td>")
            .text(lane_name(lane))
            .raw("</td><td>")
            .text(lane.class)
            .raw("</td><td class=\"num\">")
            .text(lane.weight)
            .raw("</td><td>")
            .text(
                lane.max_slots
                    .map_or_else(|| "-".to_owned(), |n| n.to_string()),
            )
            .raw("</td><td>")
            .text(may_use_text(lane, nodes))
            .raw("</td><td>")
            .text(projects_text(lane))
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

fn scheduling_section(h: &mut Html, policy: &Policy) {
    h.raw("<section><h2>Scheduling</h2><table class=\"kv\"><tbody>");
    for (label, value) in [
        ("Busy time", format!("{} s", policy.busy_secs)),
        ("Probe limit", policy.probe_limit.to_string()),
        (
            "Production probe burst",
            policy.production_probe_burst.to_string(),
        ),
        (
            "Initial backoff",
            format!("{} s", policy.backoff_initial_secs),
        ),
        ("Maximum backoff", format!("{} s", policy.backoff_max_secs)),
    ] {
        pages::kv(h, label, &value);
    }
    h.raw("</tbody></table></section>");
}

fn headroom_section(h: &mut Html, policy: &Policy) {
    h.raw("<section><h2>Production headroom</h2><p class=\"sub\">Room only production lanes ")
        .raw("may take.</p>");
    if policy.headroom.is_empty() {
        h.raw("<p class=\"empty\">None. Normal work may take all the room.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>pool</th><th>labels</th>")
            .raw("<th>envelope</th><th class=\"num\">slots</th></tr></thead><tbody>");
        for entry in &policy.headroom {
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
                .raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section>");
}

/// `GET /capacity`.
pub(super) async fn policy_get(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let (policy, note, nodes) = blocking(move || {
        Ok((
            hub.db.capacity_policy(),
            hub.db.capacity_conversion()?,
            known_nodes(&hub)?,
        ))
    })
    .await?;
    let mut main = Html::new();
    main.raw("<h1>Capacity policy</h1><p class=\"sub\">Each runner, API key, and the other ")
        .raw("API keys together, is a lane. When several lanes wait, the one holding the least ")
        .raw("for its weight goes first, up to its max slots. A runner gets work only once it ")
        .raw("has a lane, only on that lane's nodes and only for its projects.</p>");
    let policy = match policy {
        Ok(policy) => policy,
        Err(e) => {
            unreadable(&mut main, &e);
            return Ok(page(fleet::layout("Capacity policy", PATH, auth, &main)));
        }
    };
    if let Some(note) = &note {
        conversion_section(&mut main, note);
    }
    main.raw("<section><h2>Lanes</h2>");
    lanes_table(&mut main, &policy, &nodes);
    main.raw("</section>");
    headroom_section(&mut main, &policy);
    scheduling_section(&mut main, &policy);
    let steer = auth.session.role >= Role::Operator;
    let digest = policy.digest()?;
    let json = serde_json::to_string_pretty(&policy)?;
    main.raw("<section><h2>The whole policy</h2><p class=\"sub\">The format ")
        .raw("<code>vk-hub capacity-policy show</code> prints and ")
        .raw("<code>vk-hub capacity-policy set</code> takes.</p>");
    if steer {
        main.raw("<form class=\"wide\" method=\"post\" action=\"")
            .raw(PATH)
            .raw("\">");
        csrf_field(&mut main, auth);
        main.raw("<input type=\"hidden\" name=\"op\" value=\"")
            .raw(SET_POLICY)
            .raw("\"><input type=\"hidden\" name=\"expected\" value=\"")
            .text(&digest)
            .raw("\"><textarea name=\"policy\" rows=\"24\" spellcheck=\"false\" ")
            .raw("aria-label=\"Policy (JSON)\">")
            .text(json)
            .raw("</textarea><button>Set the policy</button></form>");
    } else {
        main.raw("<pre>").text(json).raw("</pre>");
    }
    main.raw("</section>");
    Ok(page(fleet::layout("Capacity policy", PATH, auth, &main)))
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
    h.raw("<section><h2>Capacity</h2>");
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
        .raw("<th>nodes</th></tr></thead><tbody>");
    for (lane, listed) in lanes {
        let branches = match listed {
            None => "all (any project)".to_owned(),
            Some(None) => "all".to_owned(),
            Some(Some(b)) => b.join(", "),
        };
        h.raw("<tr><td>")
            .text(lane_name(lane))
            .raw("</td><td>")
            .text(lane.class)
            .raw("</td><td>")
            .text(branches)
            .raw("</td><td>")
            .text(may_use_text(lane, nodes))
            .raw("</td></tr>");
    }
    h.raw("</tbody></table></section>");
}

/// `POST /capacity`: set the whole policy.
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
    if field(&form, "op") != Some(SET_POLICY) {
        return Ok(refused_page(
            &auth,
            PATH,
            StatusCode::BAD_REQUEST,
            "no such edit",
        ));
    }
    let hub = ui.hub.clone();
    let read = blocking(move || {
        Ok(hub
            .db
            .capacity_policy()
            .and_then(|policy| Ok((policy, hub.db.capacity_conversion()?))))
    });
    let (current, note) = match read.await? {
        Ok(read) => read,
        Err(e) => {
            let why = format!("{e:#}");
            return Ok(refused_page(&auth, PATH, StatusCode::CONFLICT, &why));
        }
    };
    let expected = field(&form, "expected").unwrap_or("").to_owned();
    if expected != current.digest()? {
        return Ok(refused_page(&auth, PATH, StatusCode::CONFLICT, STALE));
    }
    let proposed = serde_json::from_str::<Policy>(field(&form, "policy").unwrap_or(""))
        .context("not a capacity policy")
        .and_then(|p| p.validate().map(|()| p));
    let proposed = match proposed {
        Ok(proposed) => proposed,
        Err(e) => {
            let why = format!("{e:#}");
            return Ok(refused_page(&auth, PATH, StatusCode::BAD_REQUEST, &why));
        }
    };
    let changes = policy_changes(&current, &proposed);
    let held = note.as_ref().is_some_and(ConversionNote::held);
    if changes.is_empty() && !held {
        return Ok(super::clients::see_other(PATH));
    }
    let mut detail = Html::new();
    detail.raw("<ul>");
    if held {
        detail.raw("<li>Activate the policy</li>");
    }
    for change in changes {
        detail.raw("<li>").text(change).raw("</li>");
    }
    detail.raw("</ul>");
    let ask = actions::Ask {
        path: PATH.to_owned(),
        back: PATH.to_owned(),
        op: SET_POLICY.to_owned(),
        what: "Change the capacity policy? Jobs the new policy no longer allows will wait or be \
               refused.",
        detail,
        asked: ["expected", "policy"]
            .into_iter()
            .map(|name| (name, field(&form, name).unwrap_or("").to_owned()))
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
            return Ok(refused_page(&auth, PATH, status, &why));
        }
    }
    Ok(super::clients::see_other(PATH))
}

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
    use super::*;
    use crate::policy::{LaneId, LaneProject};

    #[test]
    fn old_pages_lead_to_the_policy() {
        for old in [OLD_PATH, "/capacity/tenants/web", "/clients/tenants/web"] {
            assert_eq!(moved(old).as_deref(), Some(PATH), "{old}");
        }
        assert_eq!(moved("/capacity/other"), None);
    }

    #[test]
    fn a_lane_s_nodes_and_projects_are_named() {
        let node = "0123456789abcdef0123456789abcdef";
        let nodes = [KnownNode {
            id: node.into(),
            label: "n1".into(),
        }];
        let mut lane = Lane::new(&LaneId::Runner {
            gitlab: "gl".into(),
            id: 42,
        });
        assert_eq!(may_use_text(&lane, &nodes), "any node");
        assert_eq!(projects_text(&lane), "any");
        lane.nodes = Some(vec![node.into(), "trusted".into()]);
        assert_eq!(may_use_text(&lane, &nodes), "n1, trusted");
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
        assert_eq!(projects_text(&lane), "7 · all; 8 · main, release/*");
        lane.projects = Some(vec![]);
        assert_eq!(projects_text(&lane), "none");
        assert_eq!(projects_text(&Lane::new(&LaneId::Default)), "-");
    }
}
