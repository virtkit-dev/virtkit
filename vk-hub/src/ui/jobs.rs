//! The fleet's `/jobs`, for every session: the history of the jobs the hub placed, newest
//! first, a page at a time, filtered by node, GitLab project, result, job name, branch and
//! pipeline, with what each used on its node where the node reported it
//! ([`vk_hub_proto::job::JobUsage`]) and a line summing up every job the filter matches.
//! Read only; a job's own page is GitLab's, but a failed job's result links to `/jobs/<id>`,
//! its record and the end of its output as the hub kept it ([`crate::jobs::detail`]), for
//! when GitLab's trace is cut or out of reach.
//!
//! The newest page of any filter stays live: its stream's URL carries the filter, and each
//! stream renders its own fragment, woken by [`Hub::jobs_changed`] alone. The summary reads the
//! whole history, so the streams of one filter share a rendering ([`Renders`]), which a page
//! loaded meanwhile starts from: a filter's page is read once per change to the jobs, and at
//! most twice a heartbeat for how long its jobs have run, however many pages follow it. An older
//! page stays as it was loaded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};
use vk_hub_proto::client::JobState;

use super::html::Html;
use super::pages::{self, bytes, mib};
use super::sse::Source;
use super::{Auth, Body, Ui, blocking, decode_form, field, fleet, message, page};
use crate::server::{HEARTBEAT, Hub};
use crate::store::{JobFilter, JobOutcome, JobPage, JobRow, SUMMARY_JOBS};

/// The page.
pub(super) const PATH: &str = "/jobs";

/// A job's page, `/jobs/<id>`.
pub(super) const DETAIL_PREFIX: &str = "/jobs/";

/// The event the newest page's fragment is swapped in on, from `/events/jobs[?<filter>]`.
pub(super) const EVENT: &str = "jobs";

/// Jobs per page.
const JOBS_PAGE: usize = 100;

/// The longest project the filter takes; what a job records of it is far shorter.
const MAX_TEXT: usize = 1024;

/// The filter's parameters, in the order a query carries them.
const FIELDS: [&str; 6] = ["node", "project", "result", "name", "ref", "pipeline"];

/// `GET /jobs[?node=…&project=…&result=…&name=…&ref=…&pipeline=…&before=…]`. A filter value
/// that cannot be one is ignored, as the audit log ignores a node that is not an ID. `swap`:
/// the filter's form asks for it ([`filter_swap`]).
pub(super) async fn get(
    query: Option<&str>,
    auth: &Auth,
    renders: &Arc<Renders>,
    ui: &Ui,
    swap: bool,
) -> Result<Response<Body>> {
    let query = decode_form(query.unwrap_or("").as_bytes());
    let mut filter = JobFilter::default();
    for name in FIELDS {
        if let Some(value) = field(&query, name) {
            set(&mut filter, name, value);
        }
    }
    let before = field(&query, "before").and_then(|b| b.parse().ok());
    let hub = ui.hub.clone();
    let wanted = filter.clone();
    let main = match before {
        None => {
            let renders = renders.clone();
            let newest =
                blocking(move || renders.page(&hub, &wanted, Instant::now(), swap)).await?;
            let Newest {
                fragment,
                projects,
                names,
            } = &*newest;
            history(&filter, false, fragment, projects, names)
        }
        Some(before) => {
            let (jobs, names) = blocking(move || {
                let jobs = crate::jobs::history(&hub, &wanted, Some(before), JOBS_PAGE)?;
                anyhow::Ok((jobs, hub.db.node_names()?))
            })
            .await?;
            let shown = fragment(&filter, true, &jobs, &names, crate::now_secs());
            history(&filter, true, &shown, &jobs.projects, &names)
        }
    };
    Ok(page(fleet::layout("Jobs", PATH, auth, &main)))
}

fn node(value: &str) -> Option<String> {
    vk_hub_proto::valid_id(value).then(|| value.to_string())
}

fn project(value: &str) -> Option<String> {
    (!value.is_empty() && value.len() <= MAX_TEXT).then(|| value.to_string())
}

/// A job name or branch substring with surrounding whitespace trimmed. Limit it to
/// [`vk_hub_proto::MAX_DISPLAY`] characters, like the recorded fields, to bound the cost
/// of matching every record.
fn part(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.chars().count() <= vk_hub_proto::MAX_DISPLAY)
        .then(|| value.to_string())
}

/// A pipeline's ID: digits alone, as GitLab numbers them.
fn pipeline(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|&p| p > 0)
}

/// Set field `name` from [`FIELDS`] to `value` and return whether it is valid.
/// Blank values mean "any": accept them without setting a field.
fn set(filter: &mut JobFilter, name: &str, value: &str) -> bool {
    if value.trim().is_empty() {
        return true;
    }
    match name {
        "node" => node(value).map(|v| filter.node = Some(v)),
        "project" => project(value).map(|v| filter.project = Some(v)),
        "result" => JobOutcome::parse(value).map(|v| filter.outcome = Some(v)),
        "name" => part(value).map(|v| filter.name = Some(v)),
        "ref" => part(value).map(|v| filter.git_ref = Some(v)),
        "pipeline" => pipeline(value).map(|v| filter.pipeline = Some(v)),
        _ => None,
    }
    .is_some()
}

/// Parse the filter for `/events/jobs?<query>`. Accept the page's filter values, each field
/// at most once, with empty values meaning any. Return `None` for anything else; pages never
/// request those queries.
pub(super) fn stream_filter(query: Option<&str>) -> Option<JobFilter> {
    let mut filter = JobFilter::default();
    let mut seen = [false; FIELDS.len()];
    for (name, value) in decode_form(query.unwrap_or("").as_bytes()) {
        let i = FIELDS.iter().position(|n| *n == name)?;
        if std::mem::replace(seen.get_mut(i)?, true) || !set(&mut filter, &name, &value) {
            return None;
        }
    }
    Some(filter)
}

/// The newest page of `filter`'s jobs, kept live.
pub(super) fn source(hub: &Arc<Hub>, renders: &Arc<Renders>, filter: JobFilter) -> Source {
    let changes = hub.subscribe_jobs();
    let (hub, renders) = (hub.clone(), renders.clone());
    Source::Own {
        name: EVENT,
        changes,
        render: Arc::new(move || {
            Ok(renders
                .render(&hub, &filter, Instant::now())?
                .fragment
                .clone()
                .into_string())
        }),
    }
}

/// The newest page per followed filter, shared by its streams and newly loaded pages.
#[derive(Default)]
pub(super) struct Renders {
    /// Renderings and last-request times by filter. Streams and filter form requests add
    /// entries; plain page loads do not. Entries expire after two heartbeats without a
    /// request. Streams request each heartbeat, keeping open streams' filters and those
    /// requested by a stream or form within two heartbeats.
    by_filter: Mutex<HashMap<JobFilter, (Instant, Latest)>>,
}

/// A filter's rendering, held while it is renewed.
type Latest = Arc<Mutex<Option<Rendered>>>;

struct Rendered {
    /// [`Hub::jobs_generation`] when the history was read.
    generation: u64,
    at: Instant,
    newest: Arc<Newest>,
}

impl Rendered {
    /// Whether the rendering is current at `now` for the jobs' `generation`. Expire it after
    /// half a heartbeat: streams request updates once a heartbeat, but the last rendering
    /// may be slightly younger. A full-heartbeat limit would update run times only every
    /// other heartbeat.
    fn stands(&self, generation: u64, now: Instant) -> bool {
        self.generation == generation && now.duration_since(self.at) < HEARTBEAT / 2
    }
}

/// A filter's newest page as read: the jobs, and the filter form's choices.
struct Newest {
    fragment: Html,
    projects: Vec<String>,
    names: Vec<(String, String)>,
}

impl Renders {
    /// Reuse `filter`'s newest page while it [stands](Rendered::stands) at `now`, or renew it.
    /// Concurrent streams of one filter wait for a single history read.
    fn render(&self, hub: &Hub, filter: &JobFilter, now: Instant) -> Result<Arc<Newest>> {
        let entry = {
            let mut by_filter = lock(&self.by_filter);
            by_filter.retain(|_, (asked, _)| now.duration_since(*asked) < 2 * HEARTBEAT);
            let (asked, entry) = by_filter
                .entry(filter.clone())
                .or_insert_with(|| (now, Arc::default()));
            *asked = now;
            entry.clone()
        };
        renew(&entry, hub, filter, now)
    }

    /// `filter`'s newest page for a page loaded at `now`: a stream's rendering, renewed if it
    /// no longer stands, so the stream's first update is never older; with no stream following
    /// the filter, one read for the page alone, kept for no one. For the filter's form
    /// (`swap`), whose page's stream opens at once, the rendering is kept for that stream.
    fn page(&self, hub: &Hub, filter: &JobFilter, now: Instant, swap: bool) -> Result<Arc<Newest>> {
        if swap {
            return self.render(hub, filter, now);
        }
        let entry = lock(&self.by_filter).get(filter).map(|(_, e)| e.clone());
        match entry {
            Some(entry) => renew(&entry, hub, filter, now),
            None => Ok(Arc::new(read(hub, filter)?)),
        }
    }

    /// How many filters have a rendering kept.
    #[cfg(test)]
    pub(super) fn filters(&self) -> usize {
        lock(&self.by_filter).len()
    }
}

/// `entry`'s rendering of `filter`, or a new one if it no longer stands at `now`.
fn renew(entry: &Latest, hub: &Hub, filter: &JobFilter, now: Instant) -> Result<Arc<Newest>> {
    let mut rendered = lock(entry);
    // Taken before the history is read, so a change made meanwhile renders it again.
    let generation = hub.jobs_generation();
    if let Some(r) = rendered.as_ref()
        && r.stands(generation, now)
    {
        return Ok(r.newest.clone());
    }
    let newest = Arc::new(read(hub, filter)?);
    *rendered = Some(Rendered {
        generation,
        at: now,
        newest: newest.clone(),
    });
    Ok(newest)
}

/// `filter`'s newest page, read now.
fn read(hub: &Hub, filter: &JobFilter) -> Result<Newest> {
    let jobs = crate::jobs::history(hub, filter, None, JOBS_PAGE)?;
    let names = hub.db.node_names()?;
    Ok(Newest {
        fragment: fragment(filter, false, &jobs, &names, crate::now_secs()),
        projects: jobs.projects,
        names,
    })
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A map and a rendering, each replaced whole: nothing half-written for a panic to leave.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Page body: the filter and `shown` jobs. The newest page stays live. With a cursor
/// (`paged`), keep the page as loaded and link back to the newest.
fn history(
    filter: &JobFilter,
    paged: bool,
    shown: &Html,
    projects: &[String],
    names: &[(String, String)],
) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Jobs</h1>");
    // Outside the live fragment, so an update never resets a choice being made.
    filter_form(&mut h, filter, projects, names);
    // Replace this part with the new filter's results, including the live fragment,
    // so the old stream closes and the new one opens.
    h.raw("<div id=\"").raw(RESULTS).raw("\">");
    if paged {
        h.raw("<p class=\"sub\">Older jobs, as they stood when this page was loaded; <a href=\"");
        href(&mut h, filter, None);
        h.raw("\">the newest</a> are kept up to date.</p>")
            .html(shown);
    } else {
        h.raw("<div id=\"jobs\" hx-ext=\"sse\" sse-connect=\"/events/jobs");
        query(&mut h, filter, None);
        h.raw("\" sse-swap=\"jobs\" sse-close=\"close\">")
            .html(shown)
            .raw("</div>");
    }
    h.raw("</div>");
    h
}

/// The ID of the part of the page the filter's form replaces.
const RESULTS: &str = "jobs-results";

/// Whether `headers` are those of the filter's form asking htmx for the part it replaces: a
/// stream of the new filter follows at once.
pub(super) fn filter_swap(headers: &HeaderMap) -> bool {
    headers.contains_key("hx-request")
        && headers
            .get("hx-target")
            .is_some_and(|t| t.as_bytes() == RESULTS.as_bytes())
}

/// Redirect a refused or failed filter request to a full load of the `/jobs` URI.
/// Swapping in a page without the results container would remove both the jobs and the
/// target for later filter requests.
pub(super) fn reload(uri: &str, refused: Response<Body>) -> Response<Body> {
    let Ok(to) = HeaderValue::from_str(uri) else {
        return refused;
    };
    let mut resp = Response::new(Body::default());
    resp.headers_mut().insert("hx-redirect", to);
    resp
}

/// The jobs: the summary, the table and the link to older jobs. `paged` as for [`history`].
fn fragment(
    filter: &JobFilter,
    paged: bool,
    jobs: &JobPage,
    names: &[(String, String)],
    now: u64,
) -> Html {
    let mut h = Html::new();
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
            "<p class=\"empty\" role=\"status\">none match</p>"
        });
        return h;
    }
    h.raw("<p class=\"sub\" role=\"status\">");
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
        job_table(&mut h, filter, &jobs.rows, &names, now);
    }
    if let Some(oldest) = jobs.older {
        h.raw("<p><a href=\"");
        href(&mut h, filter, Some(oldest));
        h.raw("\">Older</a></p>");
    }
    h
}

/// The page's jobs, one row each, filtered by `filter`.
fn job_table(
    h: &mut Html,
    filter: &JobFilter,
    rows: &[(u64, String, JobRow)],
    names: &HashMap<&str, &str>,
    now: u64,
) {
    h.raw("<section><table class=\"grid\"><thead><tr><th>job</th><th>project</th>")
        .raw("<th>branch</th><th>pipeline</th>")
        .raw("<th>node</th><th>result</th><th>started</th><th class=\"num\">ran</th>")
        .raw("<th class=\"num\">peak memory</th><th class=\"num\">CPU time</th>")
        .raw("<th class=\"num\">size</th></tr></thead><tbody>");
    for (_, id, j) in rows {
        job_row(h, filter, id, j, names, now);
    }
    h.raw("</tbody></table></section>");
}

/// The filter's form. Keep the selected node or project as an option even if the node was
/// removed or the project is outside the scanned history.
///
/// With htmx, selections apply immediately and typing after a 300 ms pause. Each request
/// replaces any pending request, fetches the filtered page, swaps in its jobs and updates
/// the URL for Back and bookmarking. History caching is disabled ([`super::pages`]), so
/// Back reloads the page. The button or Enter applies immediately; without htmx, the form
/// loads the page.
fn filter_form(h: &mut Html, filter: &JobFilter, projects: &[String], names: &[(String, String)]) {
    h.raw("<form id=\"jobs-filter\" class=\"filter\" method=\"get\" action=\"")
        .raw(PATH)
        .raw("\" hx-get=\"")
        .raw(PATH)
        .raw("\" hx-trigger=\"submit, change from:(#jobs-filter select), ")
        .raw("input changed delay:300ms from:(#jobs-filter input)\" hx-target=\"#")
        .raw(RESULTS)
        .raw("\" hx-select=\"#")
        .raw(RESULTS)
        .raw("\" hx-swap=\"outerHTML\" hx-push-url=\"true\" hx-sync=\"this:replace\">")
        .raw("<select name=\"node\" aria-label=\"Node\">")
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
    h.raw("</select><select name=\"project\" aria-label=\"Project\">")
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
    h.raw("</select><select name=\"result\" aria-label=\"Result\">")
        .raw("<option value=\"\">Every result</option>");
    for outcome in JobOutcome::ALL {
        h.raw("<option value=\"").raw(outcome.name()).raw("\"");
        if filter.outcome == Some(outcome) {
            h.raw(" selected");
        }
        h.raw(">").raw(outcome.label()).raw("</option>");
    }
    h.raw("</select>");
    let pipeline = filter.pipeline.map(|p| p.to_string());
    for (name, label, value) in [
        ("name", "Job name", filter.name.as_deref()),
        ("ref", "Branch", filter.git_ref.as_deref()),
    ] {
        h.raw("<input type=\"search\" name=\"")
            .raw(name)
            .raw("\" placeholder=\"")
            .raw(label)
            .raw("\" aria-label=\"")
            .raw(label)
            .raw("\" value=\"")
            .text(value.unwrap_or(""))
            .raw("\" maxlength=\"")
            .text(vk_hub_proto::MAX_DISPLAY)
            .raw("\">");
    }
    h.raw("<input type=\"number\" name=\"pipeline\" min=\"1\" placeholder=\"Pipeline\" ")
        .raw("aria-label=\"Pipeline\" value=\"")
        .text(pipeline.as_deref().unwrap_or(""))
        .raw("\"> <button>Show</button></form>");
}

/// `/jobs` with `filter`, and `before` if given, as its query.
fn href(h: &mut Html, filter: &JobFilter, before: Option<u64>) {
    h.raw(PATH);
    query(h, filter, before);
}

/// `filter`, and `before` if given, as a query string: `?` and each set field, or nothing.
/// Values are percent-encoded down to unreserved characters, so a project's, job's or
/// branch's name cannot end the attribute or add a parameter.
fn query(h: &mut Html, filter: &JobFilter, before: Option<u64>) {
    let pipeline = filter.pipeline.map(|p| p.to_string());
    let before = before.map(|b| b.to_string());
    let fields = [
        ("node", filter.node.as_deref()),
        ("project", filter.project.as_deref()),
        ("result", filter.outcome.map(JobOutcome::name)),
        ("name", filter.name.as_deref()),
        ("ref", filter.git_ref.as_deref()),
        ("pipeline", pipeline.as_deref()),
        ("before", before.as_deref()),
    ];
    let mut separator = "?";
    for (name, value) in fields {
        if let Some(value) = value {
            h.raw(separator)
                .text(name)
                .raw("=")
                .text(percent_encode(value));
            separator = "&amp;";
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

/// One job's row, in a page filtered by `filter`. Its name, project and branch are the
/// producer's, made display-safe when recorded and again here; its name, branch and pipeline
/// narrow the page to the jobs that share them; its links to GitLab are checked as every
/// external link is ([`Html::external_link`]).
fn job_row(
    h: &mut Html,
    filter: &JobFilter,
    id: &str,
    j: &JobRow,
    names: &HashMap<&str, &str>,
    now: u64,
) {
    let usage = j.result.as_ref().and_then(|r| r.usage);
    h.raw("<tr><td title=\"").text(id).raw("\">");
    match &j.name {
        Some(name) => narrowing(h, filter, |f| f.name = Some(name.clone()), name),
        None => {
            h.node(&j.title);
        }
    }
    gitlab_link(h, j.job_url.as_deref());
    h.raw("</td><td>")
        .node(j.project.as_deref().unwrap_or("-"))
        .raw("</td><td>");
    match &j.git_ref {
        Some(git_ref) => narrowing(h, filter, |f| f.git_ref = Some(git_ref.clone()), git_ref),
        None => {
            h.raw("-");
        }
    }
    h.raw("</td><td>");
    match j.pipeline {
        Some(p) => {
            narrowing(h, filter, |f| f.pipeline = Some(p), &p.to_string());
            gitlab_link(h, pipeline_url(j.job_url.as_deref(), p).as_deref());
        }
        None => {
            h.raw("-");
        }
    }
    h.raw("</td><td>");
    node_link(h, j, names);
    h.raw("</td><td>");
    // A failed job's page has why, as far as its output says; the router takes only hex.
    if j.outcome() == JobOutcome::Failed && vk_hub_proto::valid_id(id) {
        h.raw("<a href=\"").raw(DETAIL_PREFIX).text(id).raw("\">");
        result_badge(h, j);
        h.raw("</a>");
    } else {
        result_badge(h, j);
    }
    h.raw("</td><td>");
    match j.started_at {
        Some(at) => pages::at(h, at),
        None => h.raw("-"),
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
        .text(dash_or(size_text(j)))
        .raw("</td></tr>");
}

/// `label`, a producer's string, linked to the jobs `filter` matches once `narrow` has set
/// one more of its fields.
fn narrowing(h: &mut Html, filter: &JobFilter, narrow: impl FnOnce(&mut JobFilter), label: &str) {
    let mut narrowed = filter.clone();
    narrow(&mut narrowed);
    h.raw("<a href=\"");
    href(h, &narrowed, None);
    h.raw("\">").node(label).raw("</a>");
}

/// ` ↗`, linked to `url` on GitLab, or nothing when `url` is not a plain web link.
fn gitlab_link(h: &mut Html, url: Option<&str>) {
    if url.is_some_and(vk_hub_proto::is_web_link) {
        h.raw(" ").external_link(url, "↗");
    }
}

/// GitLab's page for pipeline `pipeline` of the project whose job's page is `job_url`:
/// `<project>/-/pipelines/<pipeline>` for a `<project>/-/jobs/<id>` that is a plain web link.
fn pipeline_url(job_url: Option<&str>, pipeline: u64) -> Option<String> {
    let (project, job) = job_url
        .filter(|u| vk_hub_proto::is_web_link(u))?
        .rsplit_once("/-/jobs/")?;
    if job.is_empty() || !job.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("{project}/-/pipelines/{pipeline}")).filter(|u| vk_hub_proto::is_web_link(u))
}

/// The node job `j` was sent to, linked to its page, or `-`.
fn node_link(h: &mut Html, j: &JobRow, names: &HashMap<&str, &str>) {
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
}

/// The guest job `j` ran in: `4 vCPUs, 8.0 GiB`.
fn size_text(j: &JobRow) -> Option<String> {
    let usage = j.result.as_ref().and_then(|r| r.usage);
    let size = match usage.map(|u| (u.cpus, u.mem_mib)) {
        Some((Some(cpus), Some(mem))) => Some((cpus, mem)),
        // Fall back to the placement envelope when the node did not report the guest size.
        _ => Some((j.placement.envelope.cpus, j.placement.envelope.mem_mib))
            .filter(|&(cpus, mem)| cpus > 0 && mem > 0),
    };
    size.map(|(cpus, mem)| {
        let unit = if cpus == 1 { "vCPU" } else { "vCPUs" };
        format!("{cpus} {unit}, {}", mib(mem))
    })
}

/// `GET /jobs/<id>`: job `id`'s record and, for a failed job, the end of its output
/// ([`crate::jobs::detail`]), for every session.
pub(super) async fn detail(id: &str, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let (hub, job) = (ui.hub.clone(), id.to_string());
    let found = blocking(move || {
        let Some((row, tail)) = crate::jobs::detail(&hub, &job)? else {
            return Ok(None);
        };
        anyhow::Ok(Some((row, tail, hub.db.node_names()?)))
    })
    .await?;
    let Some((row, tail, names)) = found else {
        return Ok(message(StatusCode::NOT_FOUND, "There is no such job."));
    };
    let main = job_page(id, &row, tail.as_deref(), &names, crate::now_secs());
    Ok(page(fleet::layout("Job", PATH, auth, &main)))
}

/// A job's page: its record, then for a failed job what was kept of its output.
fn job_page(
    id: &str,
    j: &JobRow,
    tail: Option<&[u8]>,
    names: &[(String, String)],
    now: u64,
) -> Html {
    let names: HashMap<&str, &str> = names
        .iter()
        .map(|(id, name)| (id.as_str(), name.as_str()))
        .collect();
    let result = j.result.as_ref();
    let usage = result.and_then(|r| r.usage);
    let mut h = Html::new();
    h.raw("<h1>")
        .node(j.name.as_deref().unwrap_or(&j.title))
        .raw("</h1>");
    h.raw("<p class=\"sub\"><code>").text(id).raw("</code>");
    if j.job_url.as_deref().is_some_and(vk_hub_proto::is_web_link) {
        h.raw(" · ")
            .external_link(j.job_url.as_deref(), "On GitLab");
    }
    h.raw(" · <a href=\"").raw(PATH).raw("\">All jobs</a></p>");
    pages::section(&mut h, "Job");
    let mut cell = Html::new();
    result_badge(&mut cell, j);
    pages::kv_html(&mut h, "Result", &cell);
    if let Some(class) = result.and_then(|r| r.failure) {
        pages::kv(&mut h, "Failure class", crate::jobs::failure_name(class));
    }
    if let Some(code) = result.and_then(|r| r.exit_code) {
        pages::kv(&mut h, "Exit code", &code.to_string());
    }
    if let Some(message) = result.and_then(|r| r.message.as_deref()) {
        pages::kv_node(&mut h, "Message", message);
    }
    pages::kv_node(&mut h, "Title", &j.title);
    pages::kv_node(&mut h, "Project", j.project.as_deref().unwrap_or("-"));
    let mut cell = Html::new();
    node_link(&mut cell, j, &names);
    pages::kv_html(&mut h, "Node", &cell);
    pages::kv_node(&mut h, "Pool", &j.placement.pool);
    pages::kv_node(&mut h, "Submitted by", &format!("key {}", j.key_name));
    for (key, at) in [
        ("Submitted", Some(j.created_at)),
        ("Started", j.started_at),
        ("Finished", j.finished_at),
        ("Settled", j.settled_at),
    ] {
        let mut cell = Html::new();
        match at {
            Some(at) => pages::at(&mut cell, at),
            None => cell.raw("-"),
        };
        pages::kv_html(&mut h, key, &cell);
    }
    pages::kv(
        &mut h,
        "Ran",
        &dash_or(j.ran_ms(now).map(crate::jobs::run_text)),
    );
    pages::kv(
        &mut h,
        "Peak memory",
        &dash_or(usage.and_then(|u| u.peak_mem_bytes).map(bytes)),
    );
    pages::kv(
        &mut h,
        "CPU time",
        &dash_or(usage.and_then(|u| u.cpu_ms).map(crate::jobs::run_text)),
    );
    pages::kv(&mut h, "Size", &dash_or(size_text(j)));
    pages::kv(&mut h, "Output", &bytes(j.output_len));
    pages::end_section(&mut h);
    if j.outcome() != JobOutcome::Failed {
        return h;
    }
    h.raw("<section><h2>End of its output</h2>");
    let Some(tail) = tail else {
        h.raw("<p class=\"empty\">none kept</p></section>");
        return h;
    };
    h.raw("<p class=\"sub\">The last ")
        .text(bytes(tail.len() as u64))
        .raw(", masked as the node streamed it.</p><pre>");
    for line in crate::jobs::readable(tail) {
        if let Some(at) = &line.at {
            // A plain `<time>`: `time.js` rewrites only those with a `datetime`.
            h.raw("<time title=\"")
                .text(at)
                .raw("\">")
                .text(at.get(11..19).unwrap_or(at))
                .raw("</time> ");
        }
        h.text(&line.text).raw("\n");
    }
    h.raw("</pre></section>");
    h
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
        let filter = JobFilter {
            project: Some("a&b".into()),
            outcome: Some(JobOutcome::Failed),
            ..JobFilter::default()
        };
        let mut h = Html::new();
        href(&mut h, &filter, Some(7));
        assert_eq!(
            h.into_string(),
            "/jobs?project=a%26b&amp;result=failed&amp;before=7"
        );
        let mut h = Html::new();
        href(&mut h, &JobFilter::default(), None);
        assert_eq!(h.into_string(), "/jobs");
        // A stream takes back the filter its page wrote.
        assert_eq!(
            stream_filter(Some("project=a%26b&result=failed")),
            Some(filter)
        );
    }

    /// Every filter field survives a query roundtrip.
    #[test]
    fn a_filter_s_query_reads_back_as_the_filter() {
        let filter = JobFilter {
            node: Some("ab".repeat(16)),
            project: Some("g/p q".into()),
            outcome: Some(JobOutcome::Running),
            name: Some("test: \"e2e\" <x>".into()),
            git_ref: Some("feature/é&x=1".into()),
            pipeline: Some(4012),
        };
        let mut h = Html::new();
        query(&mut h, &filter, None);
        let written = h.into_string();
        assert_eq!(
            written,
            format!(
                "?node={}&amp;project=g%2Fp%20q&amp;result=running\
                 &amp;name=test%3A%20%22e2e%22%20%3Cx%3E&amp;ref=feature%2F%C3%A9%26x%3D1\
                 &amp;pipeline=4012",
                "ab".repeat(16)
            )
        );
        let unescaped = written.strip_prefix('?').unwrap().replace("&amp;", "&");
        assert_eq!(stream_filter(Some(&unescaped)), Some(filter.clone()));
        // Trim surrounding whitespace from search text; empty fields mean "any".
        assert_eq!(
            stream_filter(Some("name=+build+&ref=&pipeline=&node=&project=&result=")),
            Some(JobFilter {
                name: Some("build".into()),
                ..JobFilter::default()
            })
        );
    }

    /// A row's name, branch and pipeline narrow the page it is on, escaped as any filter
    /// value is; its pipeline links to GitLab's page of it only from a plain web link.
    #[test]
    fn a_row_narrows_its_page_to_what_it_shares() {
        let filter = JobFilter {
            outcome: Some(JobOutcome::Failed),
            ..JobFilter::default()
        };
        let mut h = Html::new();
        narrowing(
            &mut h,
            &filter,
            |f| f.git_ref = Some("x\"><b>".into()),
            "x\"><b>",
        );
        assert_eq!(
            h.into_string(),
            "<a href=\"/jobs?result=failed&amp;ref=x%22%3E%3Cb%3E\">x&quot;&gt;&lt;b&gt;</a>"
        );
        assert_eq!(
            pipeline_url(Some("https://gitlab.example.com/g/p/-/jobs/7"), 40).as_deref(),
            Some("https://gitlab.example.com/g/p/-/pipelines/40")
        );
        for bad in [
            None,
            Some("javascript:alert(1)//-/jobs/7"),
            Some("https://gitlab.example.com/g/p/-/jobs/x"),
            Some("https://gitlab.example.com/g/p"),
        ] {
            assert_eq!(pipeline_url(bad, 40), None, "{bad:?}");
        }
        let mut h = Html::new();
        gitlab_link(&mut h, Some("javascript:alert(1)"));
        assert_eq!(h.into_string(), "");
    }

    /// The streams of a filter share its rendering until a job changes or it is half a
    /// heartbeat old, and a filter no stream asks for is forgotten.
    #[test]
    fn a_filter_s_rendering_is_shared_and_renewed() {
        let hub = Hub::new(Arc::new(crate::store::Db::open_memory().unwrap()), None);
        let renders = Renders::default();
        let t = Instant::now();
        let html = |filter| {
            renders
                .render(&hub, filter, t)
                .unwrap()
                .fragment
                .clone()
                .into_string()
        };
        let all = JobFilter::default();
        let failed = JobFilter {
            outcome: Some(JobOutcome::Failed),
            ..JobFilter::default()
        };
        assert!(html(&all).contains("none placed yet"));
        assert!(html(&failed).contains("none match"));
        assert_eq!(renders.filters(), 2);
        let job = super::super::tests::history_job(1, "acme/web");
        hub.db
            .submit_job(&"1".repeat(32), &job, "1", b"{}", "key gitlab", 1)
            .unwrap();
        // Unannounced, the rendering stands.
        assert!(html(&all).contains("none placed yet"));
        hub.jobs_changed();
        assert!(html(&all).contains(">build-1<"));
        // Half a heartbeat on, it is read again.
        let second = super::super::tests::history_job(2, "acme/web");
        hub.db
            .submit_job(&"2".repeat(32), &second, "2", b"{}", "key gitlab", 1)
            .unwrap();
        let later = renders.render(&hub, &all, t + HEARTBEAT / 2).unwrap();
        assert!(later.fragment.clone().into_string().contains(">build-2<"));
        // Past two heartbeats unasked, `failed` goes when another filter is asked for.
        renders.render(&hub, &all, t + 2 * HEARTBEAT).unwrap();
        assert_eq!(renders.filters(), 1);
    }

    /// A page starts from the rendering of a stream following its filter, and with none keeps
    /// nothing unless the filter's form asked for it.
    #[test]
    fn a_page_reuses_a_stream_s_rendering_and_keeps_none() {
        let hub = Hub::new(Arc::new(crate::store::Db::open_memory().unwrap()), None);
        let renders = Renders::default();
        let t = Instant::now();
        let all = JobFilter::default();
        renders.page(&hub, &all, t, false).unwrap();
        assert_eq!(renders.filters(), 0);
        let streamed = renders.render(&hub, &all, t).unwrap();
        assert!(Arc::ptr_eq(
            &renders.page(&hub, &all, t, false).unwrap(),
            &streamed
        ));
        assert_eq!(renders.filters(), 1);
        // The filter's form keeps its page's rendering for the stream that follows it.
        let failed = JobFilter {
            outcome: Some(JobOutcome::Failed),
            ..JobFilter::default()
        };
        let swapped = renders.page(&hub, &failed, t, true).unwrap();
        assert_eq!(renders.filters(), 2);
        assert!(Arc::ptr_eq(
            &renders.render(&hub, &failed, t).unwrap(),
            &swapped
        ));
    }

    /// A stream asks a heartbeat after its last ask, slightly under a heartbeat after the
    /// rendering it was served: that rendering is renewed, so run times move every heartbeat.
    #[test]
    fn a_rendering_nearly_a_heartbeat_old_is_renewed() {
        let at = Instant::now();
        let rendered = Rendered {
            generation: 1,
            at,
            newest: Arc::new(Newest {
                fragment: Html::new(),
                projects: Vec::new(),
                names: Vec::new(),
            }),
        };
        assert!(rendered.stands(1, at));
        assert!(!rendered.stands(2, at));
        let ms = std::time::Duration::from_millis(1);
        assert!(!rendered.stands(1, at + HEARTBEAT - ms));
    }

    #[test]
    fn a_stream_takes_only_a_filter_the_page_would() {
        let node = "ab".repeat(16);
        assert_eq!(stream_filter(None), Some(JobFilter::default()));
        // The form's "every", as the page reads it.
        assert_eq!(
            stream_filter(Some("node=&project=&result=")),
            Some(JobFilter::default())
        );
        assert_eq!(
            stream_filter(Some(&format!("node={node}"))),
            Some(JobFilter {
                node: Some(node),
                ..JobFilter::default()
            })
        );
        let long = "p".repeat(MAX_TEXT + 1);
        let longest = "é".repeat(vk_hub_proto::MAX_DISPLAY);
        assert_eq!(
            stream_filter(Some(&format!("name={longest}"))),
            Some(JobFilter {
                name: Some(longest.clone()),
                ..JobFilter::default()
            })
        );
        for bad in [
            format!("name={longest}e"),
            "node=xyz".to_string(),
            "result=lost".to_string(),
            format!("project={long}"),
            format!("name={long}"),
            format!("ref={long}"),
            "pipeline=0".to_string(),
            "pipeline=-1".to_string(),
            "pipeline=%2B7".to_string(),
            "pipeline=1x".to_string(),
            "pipeline=99999999999999999999999".to_string(),
            "name=a&name=b".to_string(),
            "result=failed&result=success".to_string(),
            // An older page has no stream.
            "before=3".to_string(),
            "other=1".to_string(),
        ] {
            assert_eq!(stream_filter(Some(&bad)), None, "{bad}");
        }
    }

    #[test]
    fn thousands_are_separated() {
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(10_000), "10,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }
}
