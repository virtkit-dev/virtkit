//! The fleet's `/jobs`, for every session: the history of the jobs the hub placed, newest
//! first, a page at a time, filtered by node, GitLab project and result, with what each used
//! on its node where the node reported it ([`vk_hub_proto::job::JobUsage`]) and a line summing
//! up every job the filter matches. Read only; a job's own page is GitLab's.

use std::collections::HashMap;

use anyhow::Result;
use hyper::Response;
use vk_hub_proto::client::JobState;

use super::html::Html;
use super::pages::{self, bytes, mib};
use super::{Auth, Body, Ui, blocking, decode_form, field, fleet, page};
use crate::store::{JobFilter, JobOutcome, JobPage, JobRow, SUMMARY_JOBS};

/// The page.
pub(super) const PATH: &str = "/jobs";

/// Jobs per page.
const JOBS_PAGE: usize = 100;

/// The longest project name the filter takes; GitLab's full paths are far shorter.
const MAX_PROJECT: usize = 1024;

/// `GET /jobs[?node=…&project=…&result=…&before=…]`. A filter value that cannot be one is
/// ignored, as the audit log ignores a node that is not an ID.
pub(super) async fn get(query: Option<&str>, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let query = decode_form(query.unwrap_or("").as_bytes());
    let filter = JobFilter {
        node: field(&query, "node")
            .filter(|n| vk_hub_proto::valid_id(n))
            .map(str::to_string),
        project: field(&query, "project")
            .filter(|p| !p.is_empty() && p.len() <= MAX_PROJECT)
            .map(str::to_string),
        outcome: field(&query, "result").and_then(JobOutcome::parse),
    };
    let before = field(&query, "before").and_then(|b| b.parse().ok());
    let hub = ui.hub.clone();
    let wanted = filter.clone();
    let (jobs, names) = blocking(move || {
        let jobs = crate::jobs::history(&hub, &wanted, before, JOBS_PAGE)?;
        anyhow::Ok((jobs, hub.db.node_names()?))
    })
    .await?;
    let main = history(&filter, before.is_some(), &jobs, &names, crate::now_secs());
    Ok(page(fleet::layout("Jobs", PATH, auth, &main)))
}

/// Page body: filter, summary, table and older-jobs link. `paged` means a cursor was supplied.
fn history(
    filter: &JobFilter,
    paged: bool,
    jobs: &JobPage,
    names: &[(String, String)],
    now: u64,
) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Jobs</h1>");
    filter_form(&mut h, filter, &jobs.projects, names);
    let names: HashMap<&str, &str> = names
        .iter()
        .map(|(id, name)| (id.as_str(), name.as_str()))
        .collect();
    let s = &jobs.summary;
    if s.matched == 0 {
        h.raw(if *filter == JobFilter::default() {
            "<p class=\"empty\">none placed yet: a producer such as vk-gitlab places jobs with \
             a key from <code>vk-hub keys create</code></p>"
        } else {
            "<p class=\"empty\">none match</p>"
        });
        return h;
    }
    h.raw("<p class=\"sub\">");
    if s.capped {
        h.raw("the latest ")
            .text(thousands(SUMMARY_JOBS))
            .raw(" jobs");
    } else {
        h.text(s.matched).raw(match s.matched {
            1 => " job",
            _ => " jobs",
        });
    }
    // Filtered on a result, every finished job either succeeded or did not.
    if filter.outcome.is_none()
        && let Some(rate) = s.succeeded.saturating_mul(100).checked_div(s.finished)
    {
        // Rounded down, so a single failure never reads as 100%.
        h.raw(" · ")
            .text(format!("{rate}% of {} finished succeeded", s.finished));
    }
    if let Some(median) = s.median_ms {
        h.raw(" · median run of finished jobs ")
            .text(crate::jobs::run_text(median));
    }
    h.raw("</p>");
    if jobs.rows.is_empty() {
        // Past the oldest job matched, or every job shown changed since it was stored.
        h.raw(match (jobs.older, paged) {
            (Some(_), _) => "<p class=\"empty\">none on this page</p>",
            (None, true) => "<p class=\"empty\">no older jobs</p>",
            (None, false) => "<p class=\"empty\">none match</p>",
        });
    } else {
        job_table(&mut h, &jobs.rows, &names, now);
    }
    if let Some(oldest) = jobs.older {
        h.raw("<p><a href=\"").raw(PATH).raw("?");
        query(&mut h, filter);
        h.raw("before=").text(oldest).raw("\">Older</a></p>");
    }
    h
}

/// The page's jobs, one row each.
fn job_table(h: &mut Html, rows: &[(u64, String, JobRow)], names: &HashMap<&str, &str>, now: u64) {
    h.raw("<section><table class=\"grid\"><thead><tr><th>job</th><th>project</th>")
        .raw("<th>node</th><th>result</th><th>started</th><th class=\"num\">ran</th>")
        .raw("<th class=\"num\">peak memory</th><th class=\"num\">CPU time</th>")
        .raw("<th class=\"num\">size</th></tr></thead><tbody>");
    for (_, id, j) in rows {
        job_row(h, id, j, names, now);
    }
    h.raw("</tbody></table></section>");
}

/// Node, project and result filters. Keep the selected node or project as an option even
/// if the node was removed or the project is outside the scanned history.
fn filter_form(h: &mut Html, filter: &JobFilter, projects: &[String], names: &[(String, String)]) {
    h.raw("<form class=\"filter\" method=\"get\" action=\"")
        .raw(PATH)
        .raw("\"><select name=\"node\" aria-label=\"node\">")
        .raw("<option value=\"\">Every node</option>");
    if let Some(node) = &filter.node
        && !names.iter().any(|(id, _)| id == node)
    {
        h.raw("<option value=\"")
            .text(node)
            .raw("\" selected>")
            .text(node.get(..8).unwrap_or(node))
            .raw("</option>");
    }
    let mut sorted: Vec<(&str, &str)> = names
        .iter()
        .map(|(id, name)| (id.as_str(), name.as_str()))
        .collect();
    sorted.sort_by_key(|&(id, name)| (name, id));
    for (id, name) in sorted {
        h.raw("<option value=\"").text(id).raw("\"");
        if filter.node.as_deref() == Some(id) {
            h.raw(" selected");
        }
        h.raw(">")
            .node(name)
            .raw(" (")
            .text(id.get(..8).unwrap_or(id))
            .raw(")</option>");
    }
    h.raw("</select><select name=\"project\" aria-label=\"project\">")
        .raw("<option value=\"\">Every project</option>");
    if let Some(project) = &filter.project
        && !projects.contains(project)
    {
        h.raw("<option value=\"")
            .text(project)
            .raw("\" selected>")
            .node(project)
            .raw("</option>");
    }
    for project in projects {
        h.raw("<option value=\"").text(project).raw("\"");
        if filter.project.as_ref() == Some(project) {
            h.raw(" selected");
        }
        h.raw(">").node(project).raw("</option>");
    }
    h.raw("</select><select name=\"result\" aria-label=\"result\">")
        .raw("<option value=\"\">Every result</option>");
    for outcome in JobOutcome::ALL {
        h.raw("<option value=\"").raw(outcome.name()).raw("\"");
        if filter.outcome == Some(outcome) {
            h.raw(" selected");
        }
        h.raw(">").raw(outcome.label()).raw("</option>");
    }
    h.raw("</select> <button>Show</button></form>");
}

/// `filter` as the start of a query string, each set field followed by `&amp;`. Values are
/// percent-encoded down to unreserved characters, so a project's name cannot end the `href`
/// or add a parameter.
fn query(h: &mut Html, filter: &JobFilter) {
    let fields = [
        ("node", filter.node.as_deref()),
        ("project", filter.project.as_deref()),
        ("result", filter.outcome.map(JobOutcome::name)),
    ];
    for (name, value) in fields {
        if let Some(value) = value {
            h.text(name)
                .raw("=")
                .text(percent_encode(value))
                .raw("&amp;");
        }
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// One job's row. Its name and project are the producer's, made display-safe when recorded
/// and again here; its link is checked as every external link is ([`Html::external_link`]).
fn job_row(h: &mut Html, id: &str, j: &JobRow, names: &HashMap<&str, &str>, now: u64) {
    let usage = j.result.as_ref().and_then(|r| r.usage);
    let label = j.name.as_deref().unwrap_or(&j.title);
    h.raw("<tr><td title=\"")
        .text(id)
        .raw("\">")
        .external_link(j.job_url.as_deref(), label)
        .raw("</td><td>")
        .node(j.project.as_deref().unwrap_or("-"))
        .raw("</td><td>");
    match &j.node {
        // The router takes only hex for a node's ID.
        Some(node) if vk_hub_proto::valid_id(node) => {
            h.raw("<a href=\"/node/").text(node).raw("\">");
            match names.get(node.as_str()) {
                Some(name) => h.node(name),
                None => h
                    .raw("<code>")
                    .text(node.get(..8).unwrap_or(node))
                    .raw("</code>"),
            };
            h.raw("</a>");
        }
        _ => {
            h.raw("-");
        }
    }
    h.raw("</td><td>");
    result_badge(h, j);
    h.raw("</td><td>");
    match j.started_at {
        Some(at) => pages::at(h, at),
        None => h.raw("-"),
    };
    let size = match usage.map(|u| (u.cpus, u.mem_mib)) {
        Some((Some(cpus), Some(mem))) => Some((cpus, mem)),
        // Fall back to the placement envelope when the node did not report the guest size.
        _ => Some((j.placement.envelope.cpus, j.placement.envelope.mem_mib))
            .filter(|&(cpus, mem)| cpus > 0 && mem > 0),
    };
    h.raw("</td><td class=\"num\">")
        .text(dash_or(j.ran_ms(now).map(crate::jobs::run_text)))
        .raw("</td><td class=\"num\">")
        .text(dash_or(usage.and_then(|u| u.peak_mem_bytes).map(bytes)))
        .raw("</td><td class=\"num\">")
        .text(dash_or(
            usage.and_then(|u| u.cpu_ms).map(crate::jobs::run_text),
        ))
        .raw("</td><td class=\"num\">")
        .text(dash_or(size.map(|(cpus, mem)| {
            let unit = if cpus == 1 { "vCPU" } else { "vCPUs" };
            format!("{cpus} {unit}, {}", mib(mem))
        })))
        .raw("</td></tr>");
}

/// How the job stands: its outcome's colour, with the failure's class and exit code, or the
/// stage it is in.
fn result_badge(h: &mut Html, j: &JobRow) {
    let result = j.result.as_ref();
    let text = match j.outcome() {
        JobOutcome::Running => crate::jobs::state_text(j),
        JobOutcome::Success => "success".to_string(),
        JobOutcome::Canceled => "canceled".to_string(),
        JobOutcome::Failed => {
            let class = result
                .and_then(|r| r.failure)
                .map_or("failed", crate::jobs::failure_name);
            match result.and_then(|r| r.exit_code) {
                Some(code) => format!("{class}, exit {code}"),
                None => class.to_string(),
            }
        }
    };
    h.raw(match j.outcome() {
        JobOutcome::Running if j.state == JobState::Queued => "<span class=\"badge\"",
        JobOutcome::Running => "<span class=\"badge busy\"",
        JobOutcome::Success => "<span class=\"badge ok\"",
        JobOutcome::Canceled => "<span class=\"badge warn\"",
        JobOutcome::Failed => "<span class=\"badge bad\"",
    });
    // Why it failed, in the node's words, on hover.
    if let Some(message) = result.and_then(|r| r.message.as_deref()) {
        h.raw(" title=\"").node(message).raw("\"");
    }
    h.raw(">").node(&text).raw("</span>");
}

/// `n` with a comma between thousands: `10,000`.
fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn dash_or(s: Option<String>) -> String {
    s.unwrap_or_else(pages::dash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filter_value_cannot_leave_its_parameter() {
        assert_eq!(
            percent_encode("acme/web app&x=\"<"),
            "acme%2Fweb%20app%26x%3D%22%3C"
        );
        let mut h = Html::new();
        query(
            &mut h,
            &JobFilter {
                node: None,
                project: Some("a&b".into()),
                outcome: Some(JobOutcome::Failed),
            },
        );
        assert_eq!(h.into_string(), "project=a%26b&amp;result=failed&amp;");
    }

    #[test]
    fn thousands_are_separated() {
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(10_000), "10,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }
}
