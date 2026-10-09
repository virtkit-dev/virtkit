//! The fleet's `/jobs`, for every session: the history of the jobs the hub placed, newest
//! first, a page at a time, filtered by node, GitLab project and result, with what each used
//! on its node where the node reported it ([`vk_hub_proto::job::JobUsage`]) and a line summing
//! up every job the filter matches. Read only; a job's own page is GitLab's.
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
use hyper::Response;
use vk_hub_proto::client::JobState;

use super::html::Html;
use super::pages::{self, bytes, mib};
use super::sse::Source;
use super::{Auth, Body, Ui, blocking, decode_form, field, fleet, page};
use crate::server::{HEARTBEAT, Hub};
use crate::store::{JobFilter, JobOutcome, JobPage, JobRow, SUMMARY_JOBS};

/// The page.
pub(super) const PATH: &str = "/jobs";

/// The event the newest page's fragment is swapped in on, from `/events/jobs[?<filter>]`.
pub(super) const EVENT: &str = "jobs";

/// Jobs per page.
const JOBS_PAGE: usize = 100;

/// The longest project name the filter takes; GitLab's full paths are far shorter.
const MAX_PROJECT: usize = 1024;

/// `GET /jobs[?node=…&project=…&result=…&before=…]`. A filter value that cannot be one is
/// ignored, as the audit log ignores a node that is not an ID.
pub(super) async fn get(
    query: Option<&str>,
    auth: &Auth,
    renders: &Arc<Renders>,
    ui: &Ui,
) -> Result<Response<Body>> {
    let query = decode_form(query.unwrap_or("").as_bytes());
    let filter = JobFilter {
        node: field(&query, "node").and_then(node),
        project: field(&query, "project").and_then(project),
        outcome: field(&query, "result").and_then(JobOutcome::parse),
    };
    let before = field(&query, "before").and_then(|b| b.parse().ok());
    let hub = ui.hub.clone();
    let wanted = filter.clone();
    let main = match before {
        None => {
            let renders = renders.clone();
            let newest = blocking(move || renders.page(&hub, &wanted, Instant::now())).await?;
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
    (!value.is_empty() && value.len() <= MAX_PROJECT).then(|| value.to_string())
}

/// Parse the filter for `/events/jobs?<query>`. Accept the page's filter values, each field
/// at most once, with empty values meaning any. Return `None` for anything else; pages never
/// request those queries.
pub(super) fn stream_filter(query: Option<&str>) -> Option<JobFilter> {
    let mut filter = JobFilter::default();
    let mut seen = [false; 3];
    for (name, value) in decode_form(query.unwrap_or("").as_bytes()) {
        let i = ["node", "project", "result"]
            .iter()
            .position(|n| *n == name)?;
        if std::mem::replace(seen.get_mut(i)?, true) {
            return None;
        }
        if value.is_empty() {
            continue;
        }
        match i {
            0 => filter.node = Some(node(&value)?),
            1 => filter.project = Some(project(&value)?),
            _ => filter.outcome = Some(JobOutcome::parse(&value)?),
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
    /// By filter: when a stream last asked for it, and its rendering. An entry no stream has
    /// asked for in two heartbeats is dropped — every stream asks once a heartbeat — so only
    /// the filters of open streams, and of streams closed within two heartbeats, are kept.
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
    /// the filter, one read for the page alone, kept for no one.
    fn page(&self, hub: &Hub, filter: &JobFilter, now: Instant) -> Result<Arc<Newest>> {
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
    if paged {
        h.raw("<p class=\"sub\">Older jobs, as they stood when this page was loaded; <a href=\"");
        href(&mut h, filter, None);
        h.raw("\">the newest</a> are kept up to date.</p>")
            .html(shown);
        return h;
    }
    h.raw("<div id=\"jobs\" hx-ext=\"sse\" sse-connect=\"/events/jobs");
    query(&mut h, filter, None);
    h.raw("\" sse-swap=\"jobs\" sse-close=\"close\">")
        .html(shown)
        .raw("</div>");
    h
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
        h.raw("<p><a href=\"");
        href(&mut h, filter, Some(oldest));
        h.raw("\">Older</a></p>");
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

/// `/jobs` with `filter`, and `before` if given, as its query.
fn href(h: &mut Html, filter: &JobFilter, before: Option<u64>) {
    h.raw(PATH);
    query(h, filter, before);
}

/// `filter`, and `before` if given, as a query string: `?` and each set field, or nothing.
/// Values are percent-encoded down to unreserved characters, so a project's name cannot end
/// the attribute or add a parameter.
fn query(h: &mut Html, filter: &JobFilter, before: Option<u64>) {
    let before = before.map(|b| b.to_string());
    let fields = [
        ("node", filter.node.as_deref()),
        ("project", filter.project.as_deref()),
        ("result", filter.outcome.map(JobOutcome::name)),
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
        let filter = JobFilter {
            node: None,
            project: Some("a&b".into()),
            outcome: Some(JobOutcome::Failed),
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
    /// nothing.
    #[test]
    fn a_page_reuses_a_stream_s_rendering_and_keeps_none() {
        let hub = Hub::new(Arc::new(crate::store::Db::open_memory().unwrap()), None);
        let renders = Renders::default();
        let t = Instant::now();
        let all = JobFilter::default();
        renders.page(&hub, &all, t).unwrap();
        assert_eq!(renders.filters(), 0);
        let streamed = renders.render(&hub, &all, t).unwrap();
        assert!(Arc::ptr_eq(
            &renders.page(&hub, &all, t).unwrap(),
            &streamed
        ));
        assert_eq!(renders.filters(), 1);
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
        let long = "p".repeat(MAX_PROJECT + 1);
        for bad in [
            "node=xyz".to_string(),
            "result=lost".to_string(),
            format!("project={long}"),
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
