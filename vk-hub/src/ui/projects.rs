//! `/gitlab/<instance>/projects/<project ID>`: a GitLab project's approval record, visible
//! to viewers and operators. Shows its state, who last decided it, when the hub first heard
//! of it, its first refused job and refusal count, with links to jobs and observed traffic.
//! Operators approve, reject or forget it through its server's page's action ([`super::clients`]).
//! Rejecting or forgetting an approved project requires confirmation.
//! [`super::capacity::project_section`] displays and edits its share of the capacity policy.
//!
//! The recorded path is display-safe and escaped through [`Html::node`], as on a job's page.

use anyhow::Result;
use hyper::{Response, StatusCode};

use super::clients;
use super::html::Html;
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, blocking, message, page};
use crate::egress::blocked::{Instances, project_label};
use crate::relays::RelayView;
use crate::store::{ProjectRow, ProjectState, Role};

/// Where a project's page is: under its GitLab server's, `/gitlab/<instance>/projects/<ID>`.
const PREFIX: &str = "/gitlab/";

/// Before the UI's navigation had sections: `/clients/projects/<instance>/<ID>`.
const OLD_PREFIX: &str = "/clients/projects/";

/// The page of instance `gitlab`'s project `id`.
pub(super) fn path(gitlab: &str, id: u64) -> String {
    format!("{PREFIX}{gitlab}/projects/{id}")
}

/// The instance and project ID a project's page at `path` names: an instance's name, and an ID
/// written as [`path`] writes it.
pub(super) fn target(path: &str) -> Option<(&str, u64)> {
    let (gitlab, id) = path.strip_prefix(PREFIX)?.split_once("/projects/")?;
    parse(gitlab, id)
}

/// Map a project page's `path` from before navigation sections to its current page.
pub(super) fn moved(path: &str) -> Option<String> {
    let (gitlab, id) = path.strip_prefix(OLD_PREFIX)?.split_once('/')?;
    parse(gitlab, id).map(|(gitlab, id)| self::path(gitlab, id))
}

/// An instance's name and an ID written as [`path`] writes it.
fn parse<'a>(gitlab: &'a str, id: &str) -> Option<(&'a str, u64)> {
    let n: u64 = id.parse().ok()?;
    (n > 0 && n.to_string() == id && crate::store::valid_gitlab_name(gitlab)).then_some((gitlab, n))
}

/// What the page shows.
struct Shown {
    row: ProjectRow,
    /// The instance URL posted with a decision for the store to check, as on its server's page.
    url: String,
    instances: Instances<String>,
    /// The relay that submitted its first job refused, while the hub has it.
    relay: Option<RelayView>,
    /// The capacity policy, or why this hub cannot read it.
    policy: Result<crate::policy::Policy>,
}

/// `GET /gitlab/<instance>/projects/<project ID>`.
pub(super) async fn get(gitlab: &str, id: u64, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let (hub, named) = (ui.hub.clone(), gitlab.to_string());
    let shown = blocking(move || {
        let Some(row) = hub.db.gitlab_project(&named, id)? else {
            // The capacity policy may list a project the hub has not seen yet: its page shows
            // its share, for operators to set it up before its first job. An unreadable policy
            // lists nothing: the URL stays a 404.
            let Ok(policy) = hub.db.capacity_policy() else {
                return Ok(None);
            };
            if policy.project_any(&named, id).is_none() {
                return Ok(None);
            }
            let known = hub.db.gitlab(&named)?.is_some();
            return Ok(Some(Err((policy, known))));
        };
        // Removing an instance forgets its projects; return no project if the instance vanished
        // between these reads.
        let Some(instance) = hub.db.gitlab(&named)? else {
            return Ok(None);
        };
        let relay = match &row.relay {
            Some(relay) => crate::relays::detail(&hub, relay)?,
            None => None,
        };
        Ok(Some(Ok(Shown {
            url: instance.url,
            instances: hub.db.gitlab_instances()?,
            relay,
            policy: hub.db.capacity_policy(),
            row,
        })))
    })
    .await?;
    let shown = match shown {
        Some(Ok(shown)) => shown,
        Some(Err((policy, known))) => return unseen(gitlab, id, policy, known, auth),
        None => {
            return Ok(message(
                StatusCode::NOT_FOUND,
                "The hub holds no record of this project: never seen, or forgotten.",
            ));
        }
    };
    let r = &shown.row;
    let name = if r.path.is_empty() {
        format!("project {id}")
    } else {
        r.path.clone()
    };
    let title = project_label(&name, gitlab, shown.instances.as_deref());
    let mut main = Html::new();
    main.raw("<h1>").node(&title).raw("</h1>");
    pages::section(&mut main, "Project");
    let mut cell = Html::new();
    if r.path.is_empty() {
        cell.raw("<span class=\"sub\">not known</span>");
    } else {
        cell.node(&r.path);
    }
    pages::kv_html(&mut main, "Path", &cell);
    pages::kv(&mut main, "GitLab ID", &id.to_string());
    let mut cell = Html::new();
    cell.raw("<strong>")
        .text(gitlab)
        .raw("</strong> ")
        .text(&shown.url);
    pages::kv_html(&mut main, "GitLab instance", &cell);
    let mut cell = Html::new();
    cell.raw(match r.state {
        ProjectState::Approved => "<span class=\"badge ok\">approved</span>",
        ProjectState::Pending => "<span class=\"badge warn\">pending</span>",
        ProjectState::Rejected => "<span class=\"badge bad\">rejected</span>",
    });
    pages::kv_html(&mut main, "Approval", &cell);
    if let (Some(at), Some(by)) = (r.decided_at, &r.decided_by) {
        let mut cell = Html::new();
        pages::at(&mut cell, at).raw(" by ").text(by);
        pages::kv_html(&mut main, "Last decided", &cell);
    }
    pages::kv_html(&mut main, "First heard of", &pages::at_html(r.since));
    if let Some(job) = r.first_job {
        let mut cell = Html::new();
        cell.external_link(r.first_job_url.as_deref(), &format!("#{job}"));
        if r.relay.is_some() {
            cell.raw(", submitted by relay ");
            clients::relay_cell(&mut cell, shown.relay.as_slice(), r.relay.as_deref());
        }
        pages::kv_html(&mut main, "First job refused", &cell);
    }
    pages::kv(&mut main, "Jobs refused", &r.refused.to_string());
    pages::end_section(&mut main);
    main.raw("<p>");
    if !r.path.is_empty() {
        // The jobs' filter matches the path alone, whatever instance a job came from.
        main.raw("<a href=\"")
            .raw(super::jobs::PATH)
            .raw("?project=")
            .text(super::jobs::percent_encode(&r.path))
            .raw("\">Jobs with this path</a> · ");
    }
    main.raw("<a href=\"")
        .raw(super::egress::PATH)
        .raw("?tab=observed&amp;project=")
        .text(super::jobs::percent_encode(&format!(
            "gitlab:{gitlab}:{id}"
        )))
        .raw("\">Observed traffic</a></p>");
    super::capacity::project_section(&mut main, &shown.policy, gitlab, id, auth)?;
    if auth.session.role >= Role::Operator {
        main.raw("<section><h2>Decide</h2><form method=\"post\" action=\"")
            .raw(clients::PATH)
            .raw("\">");
        csrf_field(&mut main, auth);
        main.raw("<input type=\"hidden\" name=\"gitlab\" value=\"")
            .text(gitlab)
            .raw("\"><input type=\"hidden\" name=\"url\" value=\"")
            .text(&shown.url)
            .raw("\"><input type=\"hidden\" name=\"project\" value=\"")
            .text(id)
            .raw("\"><input type=\"hidden\" name=\"from\" value=\"")
            .raw(clients::FROM_PROJECT)
            .raw("\">");
        clients::decide_buttons(&mut main, r.state);
        main.raw("</form></section>");
    }
    Ok(page(super::fleet::layout(
        &title,
        &path(gitlab, id),
        auth,
        &main,
    )))
}

/// The page of a project the capacity policy lists but the hub holds no record of: its share
/// alone. It leads to its server's page while the hub has the server (`known`), otherwise to
/// the servers' page.
fn unseen(
    gitlab: &str,
    id: u64,
    policy: crate::policy::Policy,
    known: bool,
    auth: &Auth,
) -> Result<Response<Body>> {
    let title = format!("{gitlab} project {id}");
    let mut main = Html::new();
    main.raw("<h1>")
        .text(&title)
        .raw("</h1><p class=\"sub\">The hub has not seen this project: no job of it has ")
        .raw("reached it yet. ");
    if known {
        main.raw("Approve it on <a href=\"")
            .text(clients::server_path(gitlab))
            .raw("\">its server's page</a> once one has.</p>");
    } else {
        main.raw("The hub has no GitLab server <strong>")
            .text(gitlab)
            .raw("</strong> either: add or approve it on <a href=\"")
            .raw(clients::GITLAB_PATH)
            .raw("\">GitLab servers</a> first.</p>");
    }
    super::capacity::project_section(&mut main, &Ok(policy), gitlab, id, auth)?;
    Ok(page(super::fleet::layout(
        &title,
        &path(gitlab, id),
        auth,
        &main,
    )))
}
