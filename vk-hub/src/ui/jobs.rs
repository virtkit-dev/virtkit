//! The fleet's `/jobs`, for every session: the history of the jobs the hub placed, newest
//! first, a page at a time, filtered by API key, node, GitLab project, result, job name, branch
//! and pipeline, with what each used on its node where the node reported it
//! ([`vk_hub_proto::job::JobUsage`]) and a line summing up every job the filter matches.
//! Operators set how many jobs the history keeps, over `job_history` ([`action`]). Each
//! job's result links to its page, `/jobs/<id>`: its record and its output as
//! far as the hub holds or kept it, followed while it runs ([`super::job_output`]), for when
//! GitLab's trace is cut, late or out of reach.
//!
//! The newest page of any filter stays live: its stream's URL carries the filter, and each
//! stream renders its own fragment, woken by [`Hub::jobs_changed`] alone. The summary reads the
//! whole history, so the streams of one filter share a rendering ([`Renders`]), which a page
//! loaded meanwhile starts from: a filter's page is read once per change to the jobs, and at
//! most twice a heartbeat for what it shows by the hub's clock, however many pages follow it.
//! An older page stays as it was loaded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::client::JobState;

use super::html::Html;
use super::job_network::Shown;
use super::job_output::{self, Output};
use super::pages::{self, bytes, mib};
use super::sse::Source;
use super::{Auth, Body, Ui, blocking, decode_form, field, fleet, message, page};
use crate::jobs::HistorySource;
use crate::server::{HEARTBEAT, Hub};
use crate::store::{
    JobFilter, JobOutcome, JobPage, JobRow, MAX_JOB_HISTORY, NamespaceRow, NoAccess,
    RegistryAccess, Role,
};

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
const FIELDS: [&str; 8] = [
    "key", "node", "project", "result", "name", "ref", "pipeline", "events",
];

/// `GET /jobs[?key=…&node=…&project=…&result=…&name=…&ref=…&pipeline=…&events=1&before=…]`. A
/// filter value that cannot be one is ignored, as the audit log ignores a node that is not an
/// ID. `swap`: the filter's form asks for it ([`filter_swap`]).
pub(super) async fn get(
    query: Option<&str>,
    auth: &Auth,
    renders: &Arc<Renders>,
    ui: &Ui,
    swap: bool,
) -> Result<Response<Body>> {
    let query = decode_form(query.unwrap_or("").as_bytes());
    if field(&query, READING).is_some() {
        return reading(ui).await;
    }
    let mut filter = JobFilter::default();
    for name in FIELDS {
        if let Some(value) = field(&query, name) {
            set(&mut filter, name, value);
        }
    }
    let before = field(&query, "before").and_then(|b| b.parse().ok());
    let hub = ui.hub.clone();
    let kept = blocking(move || crate::jobs::history_count(&hub)).await?;
    let hub = ui.hub.clone();
    let wanted = filter.clone();
    let mut main = match before {
        None => {
            let renders = renders.clone();
            let (newest, key_name) = blocking(move || {
                let newest = renders.page(&hub, &wanted, Instant::now(), swap)?;
                anyhow::Ok((newest, key_name(&hub, &wanted)?))
            })
            .await?;
            let Newest {
                fragment,
                projects,
                names,
            } = &*newest;
            history(
                &filter,
                false,
                fragment,
                projects,
                names,
                key_name.as_deref(),
            )
        }
        Some(before) => {
            let (jobs, names, key_name) = blocking(move || {
                let jobs = crate::jobs::history(&hub, &wanted, Some(before), JOBS_PAGE)?;
                anyhow::Ok((jobs, hub.db.node_names()?, key_name(&hub, &wanted)?))
            })
            .await?;
            let shown = fragment(&filter, true, &jobs, &names, crate::now_secs());
            history(
                &filter,
                true,
                &shown,
                &jobs.projects,
                &names,
                key_name.as_deref(),
            )
        }
    };
    history_form(&mut main, auth, kept);
    Ok(page(fleet::layout("Jobs", PATH, auth, &main)))
}

/// The query of a page waiting for the history to be read ([`reading`]).
const READING: &str = "reading";

/// `GET /jobs?reading=1`, polled by a page loaded while the history is read since the hub
/// started: nothing yet, then a full reload, for the filter's choices to be filled too.
async fn reading(ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let mut resp = Response::new(Body::default());
    if blocking(move || Ok(hub.db.job_briefs_read())).await? {
        resp.headers_mut()
            .insert("hx-refresh", HeaderValue::from_static("true"));
    } else {
        *resp.status_mut() = StatusCode::NO_CONTENT;
    }
    Ok(resp)
}

/// The form's operations: set the history's count, or clear the count set.
const SET_HISTORY: &str = "set-history";
const CLEAR_HISTORY: &str = "clear-history";

/// How many jobs the history keeps and where that comes from, outside the live fragment, with
/// an operator's form setting it: a plain POST to [`action`].
fn history_form(h: &mut Html, auth: &Auth, (count, source): (usize, HistorySource)) {
    h.raw("<section><h2>History</h2><p>The history keeps the newest ")
        .text(thousands(count))
        .raw(match source {
            HistorySource::Default => " jobs, by default.",
            HistorySource::Config => " jobs, as <code>job_history</code> in hub.toml sets it.",
            HistorySource::Ui => " jobs, as set here, over hub.toml.",
        })
        .raw("</p>");
    if auth.session.role >= Role::Operator {
        history_op(h, auth, SET_HISTORY);
        h.raw("<label>Jobs kept <input type=\"number\" name=\"count\" min=\"1\" max=\"")
            .text(MAX_JOB_HISTORY)
            .raw("\" value=\"")
            .text(count)
            .raw("\" required></label><button>Save</button></form>");
        if source == HistorySource::Ui {
            history_op(h, auth, CLEAR_HISTORY);
            h.raw("<button>Use hub.toml</button></form>");
        }
        h.raw("<p class=\"sub\">It applies at once: a lower count drops the oldest finished ")
            .raw("jobs in the background, a step at a time.</p>");
    }
    h.raw("</section>");
}

/// The start of a form posting `op` to [`action`].
fn history_op(h: &mut Html, auth: &Auth, op: &'static str) {
    h.raw("<form class=\"act\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\">");
    pages::csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .raw(op)
        .raw("\">");
}

/// `POST /jobs`: an operator sets how many jobs the history keeps (`set-history` with a
/// `count`), or clears that so `job_history` applies (`clear-history`), as the session's
/// principal; back to the page.
pub(super) async fn action(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(message(status, text)),
    };
    let count = match field(&form, "op") {
        Some(SET_HISTORY) => {
            let count = field(&form, "count").and_then(|c| c.trim().parse::<u64>().ok());
            match count.filter(|n| (1..=MAX_JOB_HISTORY).contains(n)) {
                Some(n) => Some(usize::try_from(n)?),
                None => {
                    let max = thousands(usize::try_from(MAX_JOB_HISTORY)?);
                    return Ok(message(
                        StatusCode::BAD_REQUEST,
                        &format!("Refused: the history keeps 1 to {max} jobs."),
                    ));
                }
            }
        }
        Some(CLEAR_HISTORY) => None,
        _ => return Ok(message(StatusCode::BAD_REQUEST, "No such action.")),
    };
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    blocking(move || crate::jobs::set_history(&hub, &principal, count)).await?;
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(PATH));
    Ok(resp)
}

fn key(value: &str) -> Option<String> {
    vk_hub_proto::valid_sha256(value).then(|| value.to_string())
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
        "key" => key(value).map(|v| filter.key = Some(v)),
        "node" => node(value).map(|v| filter.node = Some(v)),
        "project" => project(value).map(|v| filter.project = Some(v)),
        "result" => JobOutcome::parse(value).map(|v| filter.outcome = Some(v)),
        "name" => part(value).map(|v| filter.name = Some(v)),
        "ref" => part(value).map(|v| filter.git_ref = Some(v)),
        "pipeline" => pipeline(value).map(|v| filter.pipeline = Some(v)),
        "events" => (value.trim() == "1").then(|| filter.events = true),
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
    /// may be slightly younger. A full-heartbeat limit would renew what the page shows by the
    /// hub's clock — run times for a page without `time.js` — only every other heartbeat.
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

/// The name of the key `filter` narrows to; `None` for no key, or one no longer kept.
fn key_name(hub: &Hub, filter: &JobFilter) -> Result<Option<String>> {
    let Some(key) = &filter.key else {
        return Ok(None);
    };
    let mut rows = hub.db.api_keys_with_ids()?.into_iter();
    Ok(rows.find(|(id, _)| id == key).map(|(_, row)| row.name))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A map and a rendering, each replaced whole: nothing half-written for a panic to leave.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Page body: the filter and `shown` jobs. The newest page stays live. With a cursor
/// (`paged`), keep the page as loaded and link back to the newest. `key_name`: as for
/// [`key_chip`].
fn history(
    filter: &JobFilter,
    paged: bool,
    shown: &Html,
    projects: &[String],
    names: &[(String, String)],
    key_name: Option<&str>,
) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Jobs</h1>");
    // Outside the live fragment, so an update never resets a choice being made.
    filter_form(&mut h, filter, projects, names);
    // Replace this part with the new filter's results, including the live fragment,
    // so the old stream closes and the new one opens.
    h.raw("<div id=\"").raw(RESULTS).raw("\">");
    // Here rather than in the form, which a filter request leaves as it is, so its link
    // follows the filter.
    key_chip(&mut h, filter, key_name);
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
    if jobs.reading {
        h.raw("<p class=\"empty\" role=\"status\" hx-get=\"")
            .raw(PATH)
            .raw("?")
            .raw(READING)
            .raw("=1\" hx-trigger=\"every 2s\" hx-swap=\"none\">The hub is still reading ")
            .raw("the job history: the page reloads once it has.</p>");
        return h;
    }
    let s = &jobs.summary;
    if s.matched == 0 {
        h.raw(if *filter == JobFilter::default() {
            "<p class=\"empty\">none placed yet: a <code>vk-gitlab</code> enrolled as a relay \
             places them, or a client with a key from <code>vk-hub keys create</code></p>"
        } else {
            "<p class=\"empty\" role=\"status\">none match</p>"
        });
        return h;
    }
    h.raw("<p class=\"sub\" role=\"status\">")
        .text(thousands(s.matched))
        .raw(match s.matched {
            1 => " job",
            _ => " jobs",
        });
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
    // Live updates replace the table. Fixed widths prevent rows and running timers
    // from shifting its columns.
    h.raw("<section class=\"jobs-table\"><table class=\"grid jobs\"><colgroup>")
        .raw("<col class=\"job\"><col class=\"project\"><col class=\"branch\"><col class=\"pipeline\">")
        .raw("<col class=\"node\"><col class=\"result\"><col class=\"network\"><col class=\"started\">")
        .raw("<col class=\"prep\"><col class=\"ran\"><col class=\"mem\"><col class=\"cpu\"><col class=\"size\">")
        .raw("</colgroup><thead><tr><th>job</th><th>project</th>")
        .raw("<th>branch</th><th>pipeline</th>")
        .raw("<th>node</th><th>result</th><th>network</th><th>started</th><th class=\"num\" title=\"preparing the executor: admission, building or pulling the image, booting\">prep</th><th class=\"num\">ran</th>")
        .raw("<th class=\"num\">peak memory</th><th class=\"num\">CPU time</th>")
        .raw("<th class=\"num\">size</th></tr></thead><tbody>");
    for (_, id, j) in rows {
        job_row(h, filter, id, j, names, now);
    }
    h.raw("</tbody></table></section>");
}

/// The key `filter` narrows to, as a chip: by `key_name` or, for a key no longer kept, its
/// ID's start; its link drops the key and keeps the rest of the filter.
fn key_chip(h: &mut Html, filter: &JobFilter, key_name: Option<&str>) {
    let Some(id) = &filter.key else {
        return;
    };
    h.raw("<p><span class=\"badge\">Key: ")
        .text(key_name.unwrap_or_else(|| crate::store::short(id)))
        .raw(" <a href=\"");
    let every_key = JobFilter {
        key: None,
        ..filter.clone()
    };
    href(h, &every_key, None);
    h.raw("\" title=\"Every key's jobs\" aria-label=\"Every key's jobs\">×</a></span></p>");
}

/// The filter's form. Keep the selected node or project as an option even if the node was
/// removed or the project is outside the scanned history. A key, set only by the URL, is kept
/// hidden ([`key_chip`] shows it).
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
        .raw("change from:(#jobs-filter input[type=checkbox]), ")
        .raw("input changed delay:300ms from:(#jobs-filter input)\" hx-target=\"#")
        .raw(RESULTS)
        .raw("\" hx-select=\"#")
        .raw(RESULTS)
        .raw("\" hx-swap=\"outerHTML\" hx-push-url=\"true\" hx-sync=\"this:replace\">");
    if let Some(id) = &filter.key {
        h.raw("<input type=\"hidden\" name=\"key\" value=\"")
            .text(id)
            .raw("\">");
    }
    h.raw("<select name=\"node\" aria-label=\"Node\">")
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
        .raw("\"><label class=\"check\" title=\"Jobs during which the node saw something ")
        .raw("unusual: a virtio-fs stall the VMM detected and retried, …\">")
        .raw("<input type=\"checkbox\" name=\"events\" value=\"1\"")
        .raw(if filter.events { " checked" } else { "" })
        .raw("> With events</label> <button>Show</button></form>");
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
    let events = filter.events.then_some("1");
    let before = before.map(|b| b.to_string());
    let fields = [
        ("key", filter.key.as_deref()),
        ("node", filter.node.as_deref()),
        ("project", filter.project.as_deref()),
        ("result", filter.outcome.map(JobOutcome::name)),
        ("name", filter.name.as_deref()),
        ("ref", filter.git_ref.as_deref()),
        ("pipeline", pipeline.as_deref()),
        ("events", events),
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

pub(super) fn percent_encode(s: &str) -> String {
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
    // Its name, project and branch cut in the middle when too long for their columns, and whole
    // on hover ([`cut_middle`]), the job's name with its ID.
    h.raw("<tr><td title=\"")
        .text(id)
        .raw("\"><div class=\"fit\">");
    match &j.name {
        Some(name) => {
            let suffix = format!(" · {id}");
            narrowing_cut(
                h,
                filter,
                |f| f.name = Some(name.clone()),
                name,
                &suffix,
                NAME_TAIL,
            );
        }
        None => cut_middle(h, &j.title, &format!(" · {id}"), NAME_TAIL),
    }
    gitlab_link(h, j.job_url.as_deref());
    h.raw("</div></td><td><div class=\"fit\">");
    match &j.project {
        Some(project) => cut_middle(h, project, "", PROJECT_TAIL),
        None => {
            h.raw("-");
        }
    }
    h.raw("</div></td><td><div class=\"fit\">");
    // The commit the job ran appears on hover over the branch or its dash.
    let commit = j
        .commit
        .as_deref()
        .map(|c| format!(" @ {c}"))
        .unwrap_or_default();
    match &j.git_ref {
        Some(git_ref) => narrowing_cut(
            h,
            filter,
            |f| f.git_ref = Some(git_ref.clone()),
            git_ref,
            &commit,
            BRANCH_TAIL,
        ),
        None => {
            match &j.commit {
                Some(commit) => h.raw("<span title=\"").text(commit).raw("\">-</span>"),
                None => h.raw("-"),
            };
        }
    }
    h.raw("</div></td><td>");
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
    // The job's page has its output, live while it runs; the router takes only hex.
    if vk_hub_proto::valid_id(id) {
        h.raw("<a href=\"").raw(DETAIL_PREFIX).text(id).raw("\">");
        result_badge(h, j);
        h.raw("</a>");
    } else {
        result_badge(h, j);
    }
    events_badge(h, j);
    h.raw("</td><td>");
    network_cell(h, id, j);
    h.raw("</td><td>");
    match j.started_at {
        Some(at) => pages::at(h, at),
        None => h.raw("-"),
    };
    h.raw("</td><td class=\"num\">");
    prep(h, j, now);
    h.raw("</td><td class=\"num\">");
    ran(h, j, now);
    h.raw("</td><td class=\"num\">")
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
    narrowing_cut(h, filter, narrow, label, "", 0);
}

/// [`narrowing`], `label` cut in the middle when its column is too narrow for it, keeping its
/// last `tail` characters, and whole on hover followed by `suffix` ([`cut_middle`]); `0` keeps
/// it whole.
fn narrowing_cut(
    h: &mut Html,
    filter: &JobFilter,
    narrow: impl FnOnce(&mut JobFilter),
    label: &str,
    suffix: &str,
    tail: usize,
) {
    let mut narrowed = filter.clone();
    narrow(&mut narrowed);
    h.raw("<a href=\"");
    href(h, &narrowed, None);
    h.raw("\">");
    cut_middle(h, label, suffix, tail);
    h.raw("</a>");
}

// The last characters kept when a job's name, a branch or a project is cut.
const NAME_TAIL: usize = 8;
const BRANCH_TAIL: usize = 12;
const PROJECT_TAIL: usize = 8;
/// Splitting a head this short shows no more than the whole label: the stylesheet reserves
/// about this much (2.2em) for the head before the tail shrinks.
const MIN_HEAD: usize = 3;

/// `label`, a producer's string, as a head the stylesheet cuts short with an ellipsis and its
/// last `tail` characters, which stay: a long name loses its middle, not its end, which is
/// often what tells two branches apart. Whole, and read as one, when its column is wide
/// enough, and on hover, followed by `suffix`. A label hardly longer than `tail` is not split,
/// only cut at its end if need be; with `tail` 0 it is left whole. The split is between
/// `char`s, so it may part a letter from a combining mark, which shows only while the label is
/// cut.
fn cut_middle(h: &mut Html, label: &str, suffix: &str, tail: usize) {
    let safe = vk_hub_proto::display_safe(label);
    if tail == 0 {
        h.text(&safe);
        return;
    }
    h.raw("<span class=\"mid\" title=\"")
        .text(&safe)
        .text(suffix)
        .raw("\"><span class=\"head\">");
    let count = safe.chars().count();
    if count <= tail + MIN_HEAD {
        h.text(&safe).raw("</span></span>");
        return;
    }
    let split = safe
        .char_indices()
        .nth(count - tail)
        .map_or(safe.len(), |(i, _)| i);
    let (head, end) = safe.split_at(split);
    h.text(head)
        .raw("</span><span class=\"tail\">")
        .text(end)
        .raw("</span></span>");
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
    crate::jobs::size_text(j, mib)
}

/// `GET /jobs/<id>`: job `id`'s record and its output as far as the hub holds it, for every
/// session ([`job_output`]).
pub(super) async fn detail(id: &str, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let (hub, job) = (ui.hub.clone(), id.to_string());
    let found = blocking(move || {
        let Some((row, stretch)) =
            crate::jobs::output_stretch(&hub, &job, None, job_output::OPENING)?
        else {
            return Ok(None);
        };
        let output = match stretch {
            Some(stretch) => Output::Held(stretch),
            None => match hub.db.job_tail(&job)? {
                Some(tail) => Output::Kept(tail),
                None => Output::Gone,
            },
        };
        let registry = access_registry(&hub, &row)?;
        let reports = reports_egress(&hub, &row)?;
        let names = hub.db.node_names()?;
        anyhow::Ok(Some((
            row,
            output,
            names,
            registry,
            reports,
            hub.db.sole_gitlab()?,
        )))
    })
    .await?;
    let Some((row, output, names, registry, reports, sole)) = found else {
        return Ok(message(StatusCode::NOT_FOUND, "There is no such job."));
    };
    let main = job_page(
        id,
        &row,
        &output,
        &names,
        registry.as_ref(),
        Shown {
            reports,
            propose: auth.session.role >= Role::Operator,
            sole: sole.as_deref(),
        },
        crate::now_secs(),
    );
    Ok(page(fleet::layout("Job", PATH, auth, &main)))
}

/// Whether job `row`'s node announces egress reports now, as a running job's page says.
pub(super) fn reports_egress(hub: &Hub, row: &JobRow) -> Result<bool> {
    let Some(node) = row.node.as_deref() else {
        return Ok(false);
    };
    Ok(hub
        .db
        .node(node)?
        .and_then(|n| n.inventory)
        .is_some_and(|i| i.egress_reports))
}

/// The job's registry name and namespaces, if still known to the hub.
/// Namespaces name the job's storage areas.
pub(super) type AccessRegistry = (String, Vec<NamespaceRow>);

/// [`AccessRegistry`] for job `row`.
pub(super) fn access_registry(hub: &Hub, row: &JobRow) -> Result<Option<AccessRegistry>> {
    let (Some(RegistryAccess::Issued { registry, .. })
    | Some(RegistryAccess::None {
        registry: Some(registry),
        ..
    })) = &row.registry_access
    else {
        return Ok(None);
    };
    Ok(match hub.db.registry(registry)? {
        Some(r) => Some((r.hostname, hub.db.namespaces(registry)?)),
        None => None,
    })
}

/// The registry access the job got at its latest placement, ending its record, which follows
/// a re-placement: per storage area, its rights in plain words, with the token's prefixes,
/// expiry and ID under *Technical details*; or the one reason it got none, with where to fix
/// it. `registry` is the registry's name and namespaces, when the hub still knows it.
fn registry_access(
    h: &mut Html,
    access: &RegistryAccess,
    registry: Option<&(String, Vec<NamespaceRow>)>,
) {
    let registry_link = |h: &mut Html, id: &str, suffix: &'static str| {
        h.raw("<a href=\"")
            .raw(super::registries::DETAIL_PREFIX)
            .text(id)
            .raw(suffix)
            .raw("\">");
        match registry {
            Some((name, _)) if !name.is_empty() => h.node(name),
            _ => h.text(id.get(..8).unwrap_or(id)),
        };
        h.raw("</a>");
    };
    h.raw("<section class=\"job-access\"><h2>Registry access</h2>");
    match access {
        RegistryAccess::Issued {
            registry: id,
            grants,
            expires_at,
            jti,
        } => {
            h.raw("<p><span class=\"badge ok\">Issued</span> for ");
            registry_link(h, id, "?tab=access");
            h.raw("</p><ul class=\"access\">");
            let namespaces = registry.map(|(_, ns)| ns.as_slice()).unwrap_or(&[]);
            for g in grants {
                let label = super::access::source(namespaces, g)
                    .map(|ns| super::access::label(&ns.name))
                    .unwrap_or_else(|| g.prefix.clone());
                h.raw("<li>")
                    .text(&label)
                    .raw(": <strong>")
                    .text(super::access::rights(g.read, g.write, g.lock))
                    .raw("</strong></li>");
            }
            h.raw("</ul><details class=\"fold\"><summary>Technical details</summary><p>");
            for (i, g) in grants.iter().enumerate() {
                if i > 0 {
                    h.raw(" · ");
                }
                h.raw("<code>")
                    .text(&g.prefix)
                    .raw("</code> ")
                    .text(g.rights());
            }
            h.raw("</p><p class=\"sub\">Expires ");
            pages::time(h, *expires_at, &crate::utc(*expires_at));
            h.raw(" · token ID <code>")
                .text(jti)
                .raw("</code> · the token itself is never stored or shown.</p></details>");
        }
        RegistryAccess::None {
            reason,
            registry: id,
            url,
        } => {
            h.raw("<p><span class=\"badge warn\">Unavailable</span></p><p>");
            match (reason, id) {
                (NoAccess::UnboundKey, _) => {
                    h.raw("Its relay was removed, or its GitLab server is no longer approved. ")
                        .raw("<a href=\"")
                        .raw(super::clients::PATH)
                        .raw("\">Connections</a>");
                }
                (NoAccess::NodeWithoutJobTokens, _) => {
                    h.raw("Its node does not announce job tokens: it runs an older ")
                        .raw("<code>vk</code>, or has sent no inventory yet.");
                }
                (NoAccess::UnknownRegistry, _) => match url {
                    Some(url) => {
                        h.raw("Its node reaches its registry at <code>")
                            .node(url)
                            .raw("</code>, an address no registry is bound to. <a href=\"")
                            .raw(super::registries::PATH)
                            .raw("\">Registries</a>");
                    }
                    None => {
                        h.raw("Its node names no registry.");
                    }
                },
                (NoAccess::RegistryTakesNoTokens, Some(id)) => {
                    registry_link(h, id, "?tab=access");
                    h.raw(" does not take the hub's tokens: <code>[hub] tokens = true</code> ")
                        .raw("in its config turns it on.");
                }
                (NoAccess::NoAppliedKey, Some(id)) => {
                    registry_link(h, id, "?tab=settings");
                    h.raw(" had applied no signing key yet.");
                }
                (NoAccess::MintFailed, _) => {
                    h.raw("Minting its token failed: the hub's log says why.");
                }
                _ => {
                    h.raw("The hub gave it none.");
                }
            }
            h.raw("</p>");
        }
        RegistryAccess::Unknown => {
            h.raw("<p>The hub gave it none.</p>");
        }
    }
    h.raw("</section>");
}

/// A job's page: its record, then its output. While the job runs, both follow it.
fn job_page(
    id: &str,
    j: &JobRow,
    output: &Output,
    names: &[(String, String)],
    registry: Option<&AccessRegistry>,
    network: Shown<'_>,
    now: u64,
) -> Html {
    let names: HashMap<&str, &str> = names
        .iter()
        .map(|(id, name)| (id.as_str(), name.as_str()))
        .collect();
    let live = j.state != JobState::Finished && matches!(output, Output::Held(_));
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
    // The output to the left, the record beside it, as GitLab lays out a job.
    // The router takes only hex for a job's ID.
    if live && vk_hub_proto::valid_id(id) {
        h.raw("<div class=\"job-page\" hx-ext=\"sse\" sse-connect=\"")
            .raw(job_output::EVENTS)
            .text(id)
            .raw("\" sse-close=\"close\"><div class=\"job-output\">");
        job_output::section(&mut h, j, output, true);
        h.raw("</div><aside id=\"job-record\" sse-swap=\"")
            .raw(job_output::RECORD)
            .raw("\">");
        record(&mut h, j, &names, registry, network, now);
        h.raw("</aside></div>");
    } else {
        h.raw("<div class=\"job-page\"><div class=\"job-output\">");
        job_output::section(&mut h, j, output, false);
        h.raw("</div><aside id=\"job-record\">");
        record(&mut h, j, &names, registry, network, now);
        h.raw("</aside></div>");
    }
    h
}

/// Preparation duration, updated by the browser while preparation continues.
fn prep(h: &mut Html, j: &JobRow, now: u64) {
    let text = dash_or(j.prepare_ms(now).map(crate::jobs::run_text));
    match j.preparing_since() {
        Some(at) => h
            .raw("<span data-since=\"")
            .text(crate::utc(at))
            .raw("\">")
            .text(text)
            .raw("</span>"),
        None => h.text(text),
    };
}

/// Job `j`'s elapsed run time. While running, `data-since` holds its start time so
/// `time.js` advances the duration each second between page updates.
fn ran(h: &mut Html, j: &JobRow, now: u64) {
    let text = dash_or(j.ran_ms(now).map(crate::jobs::run_text));
    match j.running_since() {
        Some(at) => h
            .raw("<span data-since=\"")
            .text(crate::utc(at))
            .raw("\">")
            .text(text)
            .raw("</span>"),
        None => h.text(text),
    };
}

/// A job's displayed record, ending with registry access if recorded, then its network
/// access. `registry` comes from [`access_registry`], `network.reports` from
/// [`reports_egress`].
pub(super) fn record(
    h: &mut Html,
    j: &JobRow,
    names: &HashMap<&str, &str>,
    registry: Option<&AccessRegistry>,
    network: Shown<'_>,
    now: u64,
) {
    let result = j.result.as_ref();
    let usage = result.and_then(|r| r.usage);
    pages::section(h, "Job");
    let mut cell = Html::new();
    result_badge(&mut cell, j);
    pages::kv_html(h, "Result", &cell);
    if let Some(class) = result.and_then(|r| r.failure) {
        pages::kv(h, "Failure class", crate::jobs::failure_name(class));
    }
    if let Some(code) = result.and_then(|r| r.exit_code) {
        pages::kv(h, "Exit code", &code.to_string());
    }
    if let Some(message) = result.and_then(|r| r.message.as_deref()) {
        pages::kv_node(h, "Message", message);
    }
    // Show each kind, count and first occurrence, as in `vk-hub jobs show`. Keep the full
    // sanitized detail: its ending explains what happened and can exceed the field limit.
    for event in result.map_or(&[][..], |r| &r.events) {
        pages::kv(h, "Event", &event.to_string());
    }
    pages::kv_node(h, "Title", &j.title);
    pages::kv_node(h, "Project", j.project.as_deref().unwrap_or("-"));
    if j.git_ref.is_some() || j.commit.is_some() {
        // The branch and the commit it ran, abbreviated with the full commit on hover.
        let mut cell = Html::new();
        cell.node(j.git_ref.as_deref().unwrap_or("-"));
        if let Some(commit) = &j.commit {
            cell.raw(" @ <code title=\"")
                .text(commit)
                .raw("\">")
                .text(commit.get(..12).unwrap_or(commit))
                .raw("</code>");
        }
        pages::kv_html(h, "Branch", &cell);
    }
    let mut cell = Html::new();
    node_link(&mut cell, j, names);
    pages::kv_html(h, "Node", &cell);
    pages::kv_node(h, "Pool", &j.placement.pool);
    pages::kv_node(h, "Submitted by", &format!("key {}", j.key_name));
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
        pages::kv_html(h, key, &cell);
    }
    if let Some(activity) = &j.activity {
        let mut cell = Html::new();
        activity_cell(&mut cell, activity);
        pages::kv_html(h, "Doing", &cell);
    }
    let mut cell = Html::new();
    prep(&mut cell, j, now);
    pages::kv_html(h, "Prepared in", &cell);
    let mut cell = Html::new();
    ran(&mut cell, j, now);
    pages::kv_html(h, "Ran", &cell);
    pages::kv(
        h,
        "Peak memory",
        &dash_or(usage.and_then(|u| u.peak_mem_bytes).map(bytes)),
    );
    pages::kv(
        h,
        "CPU time",
        &dash_or(usage.and_then(|u| u.cpu_ms).map(crate::jobs::run_text)),
    );
    pages::kv(h, "Size", &dash_or(size_text(j)));
    pages::kv(h, "Output", &bytes(j.output_len));
    pages::end_section(h);
    if let Some(access) = &j.registry_access {
        registry_access(h, access, registry);
    }
    if let Some(applied) = &j.egress_rules {
        h.raw("<section class=\"job-access\"><h2>Hub egress rules</h2><p>")
            .text(crate::egress::rules_applied_text(applied))
            .raw("</p></section>");
    }
    let node = j
        .node
        .as_deref()
        .map(|n| names.get(n).copied().unwrap_or(n));
    super::job_network::section(h, j, node, network);
}

/// What the job's preparation does, whole: the image, and who builds or pulls it when the job
/// waits — a GitLab job, linked when its URL is a plain web link.
fn activity_cell(h: &mut Html, activity: &vk_hub_proto::dispatch::Activity) {
    use vk_hub_proto::dispatch::Activity;
    match activity {
        Activity::Building { image } => {
            h.raw("building ").raw("<code>").node(image).raw("</code>");
        }
        Activity::Pulling { image } => {
            h.raw("pulling ").raw("<code>").node(image).raw("</code>");
        }
        Activity::Waiting {
            image,
            building,
            holder,
        } => {
            h.raw("waiting for ");
            match holder {
                Some(holder) => {
                    h.external_link(Some(holder), holder);
                }
                None => {
                    h.raw("another job");
                }
            }
            h.raw(if *building { " to build " } else { " to pull " })
                .raw("<code>")
                .node(image)
                .raw("</code>");
        }
        Activity::Other => {
            h.raw("preparing");
        }
    }
}

/// How the job stands: its outcome's colour, with the failure's class and exit code, or the
/// stage it is in — what it does, while it prepares.
pub(super) fn result_badge(h: &mut Html, j: &JobRow) {
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

/// What the node saw happen to the job, beside its result: `virtio-fs stall ×2`, the end of
/// each event's first occurrence on hover. Nothing for a job without events.
fn events_badge(h: &mut Html, j: &JobRow) {
    let Some(events) = j.result.as_ref().map(|r| &r.events) else {
        return;
    };
    let Some(text) = crate::jobs::events_summary(events) else {
        return;
    };
    let details: Vec<String> = events.iter().map(|e| tail(&e.detail, TITLE_TAIL)).collect();
    h.raw("<span class=\"badge warn event\" title=\"")
        .text(details.join("\n"))
        .raw("\">")
        .node(&text)
        .raw("</span>");
}

/// What the job's node reported of its egress, in short ([`crate::egress::Summary::headline`]),
/// everything counted on hover; whether reporting is pending or unavailable; `-` for a job that
/// never ran on a node. What was refused links to the job's rows on the Egress page.
fn network_cell(h: &mut Html, id: &str, j: &JobRow) {
    use crate::egress::{Network, Summary, Tone};
    match crate::egress::network(j) {
        Network::NotRun => {
            h.raw("-");
        }
        Network::Pending => {
            h.raw("<span class=\"sub\" title=\"Nothing reported yet\">pending</span>");
        }
        Network::Unavailable => {
            h.raw("<span class=\"sub\" title=\"Its node sent no egress report: this does not ")
                .raw("mean the job made no network attempts\">unavailable</span>");
        }
        Network::Reported(report) => {
            let summary = Summary::of(report);
            match summary.headline() {
                (Tone::Ok, text) => {
                    h.raw("<span class=\"sub\" title=\"")
                        .text(summary.text())
                        .raw("\">")
                        .text(text.to_lowercase())
                        .raw("</span>");
                }
                (tone, text) => {
                    use crate::egress::blocked::View;
                    let view = if summary.refusals > 0 {
                        Some(View::Refused)
                    } else if summary.blocked.any() {
                        Some(View::Blocked)
                    } else if summary.would_block.any() {
                        Some(View::WouldBlock)
                    } else if summary.unreachable > 0 {
                        Some(View::Refused)
                    } else {
                        None
                    };
                    if let Some(view) = view {
                        h.raw("<a href=\"")
                            .text(super::egress::job_href(id, view))
                            .raw("\">");
                    }
                    super::job_network::badge(h, tone, &text, Some(&summary.text()));
                    if view.is_some() {
                        h.raw("</a>");
                    }
                }
            }
        }
    }
}

/// The most characters of each event's detail the events badge shows on hover: its end, which
/// says what happened. The job's page has them whole.
const TITLE_TAIL: usize = 160;

/// The last `max` characters of `s`, after a "…" when it has more.
fn tail(s: &str, max: usize) -> String {
    match s.char_indices().rev().nth(max) {
        Some((at, c)) => format!("…{}", &s[at + c.len_utf8()..]),
        None => s.to_string(),
    }
}

/// `n` with a comma between thousands: `10,000`.
pub(super) fn thousands(n: usize) -> String {
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

    /// A finished job's record as a busy fleet's are, 1.5 KB of JSON on average: usage, and
    /// for every other job an egress report and a registry token. `n` varies its project
    /// (40), name (200), node (8), branch, pipeline and outcome (one in ten fails, one in
    /// fifty is canceled).
    fn bench_job(n: u64) -> JobRow {
        let mut row: JobRow = serde_json::from_str(include_str!("bench_job.json")).unwrap();
        let project = format!("group/project-{}", n % 40);
        let name = format!("build: [variant-{}]", n % 200);
        row.request_id = format!("{n:032x}");
        row.title = format!("GitLab job {n} of {project} ({name})");
        row.project = Some(project);
        row.name = Some(name);
        row.git_ref = Some(format!("release-{}", n % 25));
        row.pipeline = Some(500_000 + n / 20);
        row.node = Some(format!("{:032x}", n % 8));
        row.created_at = 1_700_000_000 + n * 30;
        row.started_at = Some(row.created_at + 5);
        row.finished_at = Some(row.created_at + 600 + n % 300);
        row.settled_at = row.finished_at;
        if let Some(result) = row.result.as_mut() {
            result.failure = match n % 50 {
                0 => Some(vk_hub_proto::job::FailureClass::Canceled),
                m if m % 10 == 1 => Some(vk_hub_proto::job::FailureClass::Script),
                _ => None,
            };
            if let Some(usage) = result.usage.as_mut() {
                usage.wall_ms = 600_000 + (n % 300) * 1000;
            }
            if n.is_multiple_of(2) {
                result.egress = None;
                row.registry_access = None;
            }
        }
        row
    }

    /// How long a hub takes to read a 100,000-job history at start, then the newest page of
    /// it to render, unfiltered and filtered. Measure an optimized build,
    /// which `./dev.sh` builds under a profile of another name than `release`:
    /// `./dev.sh test -p vk-hub --bin vk-hub --config 'profile.opt.inherits="release"'
    /// --profile opt jobs_page_bench -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn jobs_page_bench() {
        let dir = std::env::temp_dir().join(format!("vk-hub-jobs-bench-{}", std::process::id()));
        let db = Arc::new(crate::store::Db::open(&dir.join("hub.db")).unwrap());
        for chunk in (0..100_000u64).collect::<Vec<_>>().chunks(10_000) {
            db.fill_history(chunk.iter().map(|&n| (format!("{n:032x}"), bench_job(n))))
                .unwrap();
        }
        let start = Instant::now();
        db.read_job_briefs().unwrap();
        println!(
            "JOBS PAGE reading the history at start: {:?}",
            start.elapsed()
        );
        let hub = Hub::new(db, None);
        let filters = [
            ("unfiltered", JobFilter::default()),
            (
                "project",
                JobFilter {
                    project: Some("group/project-7".into()),
                    ..JobFilter::default()
                },
            ),
            (
                "failed",
                JobFilter {
                    outcome: Some(JobOutcome::Failed),
                    ..JobFilter::default()
                },
            ),
            (
                "name substring",
                JobFilter {
                    name: Some("VARIANT-17]".into()),
                    ..JobFilter::default()
                },
            ),
            (
                "matching nothing",
                JobFilter {
                    project: Some("group/none".into()),
                    ..JobFilter::default()
                },
            ),
        ];
        for (what, filter) in filters {
            read(&hub, &filter).unwrap();
            let runs = 5;
            let start = Instant::now();
            for _ in 0..runs {
                std::hint::black_box(read(&hub, &filter).unwrap());
            }
            println!("JOBS PAGE {what}: {:?}", start.elapsed() / runs);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A job's events show on its page, each with its whole detail escaped, and beside its
    /// result in the jobs table, the details on hover; a job without any shows neither.
    #[test]
    fn a_job_s_events_show_on_its_page_and_in_the_table() {
        use vk_hub_proto::job::{JobEvent, JobEventKind, JobResult};
        let mut j = super::super::tests::history_job(1, "acme/web");
        j.state = JobState::Finished;
        let detail = format!("{}<b>: suspected lost interrupt", "x".repeat(300));
        j.result = Some(JobResult {
            failure: None,
            exit_code: None,
            message: None,
            output_len: 0,
            artifacts: Vec::new(),
            usage: None,
            events: vec![JobEvent::new(JobEventKind::VirtioFsStall, 2, &detail)],
            egress: None,
        });
        let mut h = Html::new();
        record(&mut h, &j, &HashMap::new(), None, Shown::default(), 1030);
        let page = h.into_string();
        let escaped = format!("{}&lt;b&gt;: suspected lost interrupt", "x".repeat(300));
        assert!(
            page.contains(&format!(
                "<th>Event</th><td>virtio-fs stall (2 times): {escaped}</td>"
            )),
            "{page}"
        );
        let mut h = Html::new();
        events_badge(&mut h, &j);
        let ending = format!("{}&lt;b&gt;: suspected lost interrupt", "x".repeat(131));
        assert_eq!(
            h.into_string(),
            format!(
                "<span class=\"badge warn event\" title=\"…{ending}\">virtio-fs stall ×2</span>"
            )
        );
        // An uncounted event, from a peer that sent no count, shows as once.
        j.result.as_mut().unwrap().events[0].count = 0;
        let mut h = Html::new();
        events_badge(&mut h, &j);
        assert!(h.into_string().ends_with(">virtio-fs stall ×1</span>"));
        j.result.as_mut().unwrap().events.clear();
        let mut h = Html::new();
        events_badge(&mut h, &j);
        assert_eq!(h.into_string(), "");
        let mut h = Html::new();
        record(&mut h, &j, &HashMap::new(), None, Shown::default(), 1030);
        assert!(!h.into_string().contains("<th>Event</th>"));
    }

    /// Show preparation activity and a browser timer; link the awaited job only through
    /// a plain web link.
    #[test]
    fn a_preparing_job_s_record_says_what_it_does() {
        use vk_hub_proto::dispatch::Activity;
        let mut j = super::super::tests::history_job(1, "acme/web");
        j.state = JobState::Running;
        j.started_at = Some(1000);
        j.stage = Some(crate::store::PREPARE_STAGE.into());
        let page = |j: &JobRow| {
            let mut h = Html::new();
            record(&mut h, j, &HashMap::new(), None, Shown::default(), 1030);
            h.into_string()
        };
        // Nothing said yet: preparing, for 30 seconds so far.
        let shown = page(&j);
        assert!(shown.contains(">preparing</span>"), "{shown}");
        assert!(!shown.contains("Doing"), "{shown}");
        assert!(
            shown.contains(&format!(
                "<th>Prepared in</th><td><span data-since=\"{}\">30s</span>",
                crate::utc(1000)
            )),
            "{shown}"
        );
        assert!(shown.contains("<th>Ran</th><td>-</td>"), "{shown}");
        let url = "https://gitlab.example.com/g/p/-/jobs/1";
        j.activity = Some(Activity::Waiting {
            image: "docker/<x>".into(),
            building: true,
            holder: Some(url.into()),
        });
        let shown = page(&j);
        assert!(shown.contains(">waiting for build</span>"), "{shown}");
        assert!(
            shown.contains(&format!(
                "<th>Doing</th><td>waiting for <a href=\"{url}\" target=\"_blank\" \
                 rel=\"noopener noreferrer\">{url}</a> to build <code>docker/&lt;x&gt;</code>"
            )),
            "{shown}"
        );
        let doing = |activity| {
            let mut h = Html::new();
            activity_cell(&mut h, &activity);
            h.into_string()
        };
        assert_eq!(
            doing(Activity::Waiting {
                image: "img".into(),
                building: false,
                holder: Some("javascript:alert(1)".into()),
            }),
            "waiting for javascript:alert(1) to pull <code>img</code>"
        );
        assert_eq!(
            doing(Activity::Waiting {
                image: "img".into(),
                building: true,
                holder: None,
            }),
            "waiting for another job to build <code>img</code>"
        );
        assert_eq!(doing(Activity::Other), "preparing");
    }

    /// A long name is split into a head the stylesheet may cut and a tail that stays; a short
    /// one is not split, and what it holds is escaped either way.
    #[test]
    fn a_long_name_keeps_its_tail() {
        let cut = |label: &str, tail: usize| {
            let mut h = Html::new();
            cut_middle(&mut h, label, "", tail);
            h.into_string()
        };
        assert_eq!(
            cut("integration/master-staging/she", 12),
            "<span class=\"mid\" title=\"integration/master-staging/she\">\
             <span class=\"head\">integration/master</span>\
             <span class=\"tail\">-staging/she</span></span>"
        );
        assert_eq!(
            cut("dev-team-core", 12),
            "<span class=\"mid\" title=\"dev-team-core\"><span class=\"head\">dev-team-core</span></span>"
        );
        assert_eq!(
            cut("élan-<x>-très-long-nom", 5),
            "<span class=\"mid\" title=\"élan-&lt;x&gt;-très-long-nom\">\
             <span class=\"head\">élan-&lt;x&gt;-très-lon</span>\
             <span class=\"tail\">g-nom</span></span>"
        );
        assert_eq!(cut("77", 0), "77");
    }

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
            key: Some("cd".repeat(32)),
            node: Some("ab".repeat(16)),
            project: Some("g/p q".into()),
            outcome: Some(JobOutcome::Running),
            name: Some("test: \"e2e\" <x>".into()),
            git_ref: Some("feature/é&x=1".into()),
            pipeline: Some(4012),
            events: true,
        };
        let mut h = Html::new();
        query(&mut h, &filter, None);
        let written = h.into_string();
        assert_eq!(
            written,
            format!(
                "?key={}&amp;node={}&amp;project=g%2Fp%20q&amp;result=running\
                 &amp;name=test%3A%20%22e2e%22%20%3Cx%3E&amp;ref=feature%2F%C3%A9%26x%3D1\
                 &amp;pipeline=4012&amp;events=1",
                "cd".repeat(32),
                "ab".repeat(16)
            )
        );
        let unescaped = written.strip_prefix('?').unwrap().replace("&amp;", "&");
        assert_eq!(stream_filter(Some(&unescaped)), Some(filter.clone()));
        // Trim surrounding whitespace from search text; empty fields mean "any".
        assert_eq!(
            stream_filter(Some(
                "name=+build+&ref=&pipeline=&key=&node=&project=&result="
            )),
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
        // The "With events" checkbox, ticked or not.
        assert_eq!(
            stream_filter(Some("pipeline=&events=1")),
            Some(JobFilter {
                events: true,
                ..JobFilter::default()
            })
        );
        assert_eq!(stream_filter(Some("events=")), Some(JobFilter::default()));
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
            "events=0".to_string(),
            "events=yes".to_string(),
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

    /// The Network column says what was blocked first, everything counted on hover, and keeps
    /// a job without a report apart from one that reached nothing.
    #[test]
    fn a_job_s_network_shows_in_the_table() {
        use crate::egress::testing::{entry, phase};
        use vk_hub_proto::egress::{
            EgressCoverage, EgressDestination, EgressLayer, EgressOutcome, EgressPhase,
            EgressProtocol, EgressReport,
        };
        let cell = |j: &JobRow| {
            let mut h = Html::new();
            network_cell(&mut h, &"ab".repeat(16), j);
            h.into_string()
        };
        let mut j = super::super::tests::history_job(1, "acme/web");
        assert_eq!(cell(&j), "-");
        j.node = Some("n1".into());
        j.state = JobState::Running;
        assert!(cell(&j).contains(">pending<"));
        j.state = JobState::Finished;
        j.started_at = Some(1_000);
        assert!(cell(&j).contains(">unavailable<"), "{}", cell(&j));
        let mut result = vk_hub_proto::job::JobResult {
            failure: None,
            exit_code: None,
            message: None,
            output_len: 0,
            artifacts: vec![],
            usage: None,
            events: vec![],
            egress: None,
        };
        let mut report = EgressReport {
            phases: vec![phase(EgressPhase::Run, EgressCoverage::Complete)],
            ..EgressReport::default()
        };
        result.egress = Some(report.clone());
        j.result = Some(result.clone());
        assert!(cell(&j).contains(">none blocked<"), "{}", cell(&j));
        // Nothing listed of a phase the node did not record is no evidence of nothing blocked.
        report.phases[0].coverage = EgressCoverage::Unavailable;
        result.egress = Some(report.clone());
        j.result = Some(result.clone());
        assert_eq!(
            cell(&j),
            "<span class=\"badge warn\" title=\"No blocks recorded · incomplete record\">\
             Incomplete</span>"
        );
        report.phases[0].coverage = EgressCoverage::Complete;
        report.entries = vec![
            entry(
                EgressOutcome::Blocked,
                EgressProtocol::Dns,
                EgressDestination::domain("evil.example"),
                Some(EgressLayer::NodeCap),
            ),
            entry(
                EgressOutcome::Observed,
                EgressProtocol::Dns,
                EgressDestination::domain("crates.io"),
                None,
            ),
        ];
        result.egress = Some(report);
        j.result = Some(result);
        // Linked to the job's rows on the Egress page.
        assert_eq!(
            cell(&j),
            format!(
                "<a href=\"/egress?state=all&amp;job={}\"><span class=\"badge bad\" \
                 title=\"Blocked: 1 destination (1 attempt) · Observed: 1 destination (1 \
                 attempt)\">Blocked: 1 destination</span></a>",
                "ab".repeat(16)
            )
        );
    }

    /// Registry access ends the record, so record updates carry it after each placement.
    #[test]
    fn a_record_ends_with_the_job_s_registry_access() {
        use crate::store::{NoAccess, RegistryAccess};
        let mut j = super::super::tests::history_job(1, "acme/web");
        let mut h = Html::new();
        record(&mut h, &j, &HashMap::new(), None, Shown::default(), 1030);
        assert!(!h.into_string().contains("Registry access"));
        j.registry_access = Some(RegistryAccess::None {
            reason: NoAccess::MintFailed,
            registry: None,
            url: None,
        });
        let mut h = Html::new();
        record(&mut h, &j, &HashMap::new(), None, Shown::default(), 1030);
        let html = h.into_string();
        assert!(
            html.contains("<h2>Registry access</h2>") && html.contains("Minting its token failed"),
            "{html}"
        );
    }
}
