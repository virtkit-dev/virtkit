//! `/egress`: the Egress page's *Blocked* tab, for viewers and operators alike — what the jobs
//! of the history were refused, by destination and project ([`crate::egress::blocked`]), each
//! row with a page of its own, `/egress/rows/<id>`, of the latest jobs that share it and where
//! to look to allow it, by the layer that decided it. *Blocked*, *Would block* and
//! *Declaration issues* are separate views, each with its count. The inbox is the New rows of
//! projects not muted; operators acknowledge or reopen a row, and mute or unmute its project,
//! from its page, as their session's principal. The *Observed traffic* tab is [`observed`]'s,
//! the *Rules* tab [`rules`]'s. The rows and the views' counts follow the jobs' reports, a
//! running job's as its record is written with them, and the rows' triage, over
//! `/events/egress`; the filter's form and the mutes' stay out of what is swapped. A rendering
//! reads the view's rows from the store's indexes, the latest first, and at most
//! [`ROW_BUDGET`] of them in all; streams of one filter share it ([`Renders`]).
//!
//! Destinations, service names and declared entries are the jobs' or their guests' to choose:
//! each goes through [`Html::node`].

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::egress::{EgressEntry, EgressRefusal};

use super::html::Html;
use super::jobs::percent_encode;
use super::pages;
use super::sse::Source;
use super::{Auth, Body, Ui, blocking, decode_form, field, fleet, message, page};
use crate::egress::blocked::{Finding, LAYERS, PHASES, Subject, View, layer_label, row_id, shares};
use crate::egress::{self, Check};
use crate::server::{HEARTBEAT, Hub};
use crate::store::{BlockedRow, JobRow, MAX_MUTE_REASON, Mute, Role, RowRange, Stored};

mod editor;
mod observed;
mod rules;

pub(super) use editor::{ACTION_PATH as RULES_ACTION_PATH, action as rules_action};

/// The page.
pub(super) const PATH: &str = "/egress";

/// The event the page's rows are swapped in on, at `/events/egress`.
pub(super) const EVENT: &str = "egress";

/// A row's page, `/egress/rows/<id>`.
pub(super) const ROW_PREFIX: &str = "/egress/rows/";

/// The ID of the part of the page its filter's form replaces.
const RESULTS: &str = "egress-results";

/// The most rows the page lists, the latest first.
const PAGE_ROWS: usize = 200;

/// The most rows one rendering of the page reads: its view's, then those its counts read.
#[cfg(not(test))]
const ROW_BUDGET: usize = 10_000;
#[cfg(test)]
const ROW_BUDGET: usize = 300;

/// The latest jobs a row's page shows, and reads its evidence from.
const ROW_JOBS: usize = 20;

/// What the page's tabs share between their pages and streams.
#[derive(Default)]
pub(super) struct Caches {
    /// The Rules tab's reads of the history.
    aggregates: crate::egress::aggregates::Cache,
    /// The Blocked tab's streamed part, by filter.
    blocked: Renders,
}

/// The Blocked tab's streamed part per followed filter, shared by its streams.
#[derive(Default)]
struct Renders {
    /// Renderings and last-request times by filter, forgotten after two heartbeats without a
    /// request: an open stream requests one each heartbeat.
    by_filter: Mutex<HashMap<Filter, (Instant, Latest)>>,
    /// How many renderings were made.
    #[cfg(test)]
    rendered: std::sync::atomic::AtomicU64,
}

/// A filter's rendering, held while it is renewed.
type Latest = Arc<Mutex<Option<Rendered>>>;

struct Rendered {
    /// [`Hub::egress_generation`] before the rows were read.
    generation: u64,
    at: Instant,
    fragment: Arc<String>,
}

impl Rendered {
    /// Whether it stands at `now` for `generation`: for [`super::sse`]'s debounce past a
    /// change, so streams rendering within it share one rendering however fast the jobs' reports
    /// change, and for half a heartbeat at most, for the ages shown and mutes ending.
    fn stands(&self, generation: u64, now: Instant) -> bool {
        let age = now.saturating_duration_since(self.at);
        age < HEARTBEAT / 2 && (generation == self.generation || age < SHARED)
    }
}

/// How long a rendering stands past a change to the jobs' reports or the rows.
const SHARED: Duration = Duration::from_secs(1);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A map and a rendering, each replaced whole: nothing half-written for a panic to leave.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Renders {
    /// `filter`'s streamed part at `now`: the latest rendering while it stands, else a new one.
    /// Concurrent streams of one filter wait for a single one.
    fn render(&self, hub: &Hub, filter: &Filter, now: Instant) -> Result<Arc<String>> {
        let entry = {
            let mut by_filter = lock(&self.by_filter);
            by_filter.retain(|_, (asked, _)| now.saturating_duration_since(*asked) < 2 * HEARTBEAT);
            let (asked, entry) = by_filter
                .entry(filter.clone())
                .or_insert_with(|| (now, Arc::default()));
            *asked = now;
            entry.clone()
        };
        let mut rendered = lock(&entry);
        // Taken before the rows are read, so a change made meanwhile renders them again.
        let generation = hub.egress_generation();
        if let Some(r) = rendered.as_ref()
            && r.stands(generation, now)
        {
            return Ok(r.fragment.clone());
        }
        let mut h = Html::new();
        results(&mut h, filter, &listing(hub, filter)?);
        let fragment = Arc::new(h.into_string());
        #[cfg(test)]
        self.rendered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *rendered = Some(Rendered {
            generation,
            at: now,
            fragment: fragment.clone(),
        });
        Ok(fragment)
    }
}

/// The rows a page shows: those of one view, matching every set field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct Filter {
    view: Option<View>,
    subject: Option<Subject>,
    /// A [`crate::egress::blocked::layer_key`].
    layer: Option<&'static str>,
    /// A [`crate::egress::blocked::phase_key`].
    phase: Option<&'static str>,
    /// A job's ID: the rows it shares.
    job: Option<String>,
    state: State,
}

/// Which rows a page shows by how they stand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
enum State {
    /// The inbox: New rows of subjects not muted.
    #[default]
    New,
    /// Acknowledged rows of subjects not muted.
    Acknowledged,
    /// Rows of muted subjects, however they stand.
    Muted,
    All,
}

impl State {
    const ALL: [State; 4] = [State::New, State::Acknowledged, State::Muted, State::All];

    /// The query's value; empty for the default.
    fn name(self) -> &'static str {
        match self {
            State::New => "",
            State::Acknowledged => "acknowledged",
            State::Muted => "muted",
            State::All => "all",
        }
    }

    fn label(self) -> &'static str {
        match self {
            State::New => "New",
            State::Acknowledged => "Acknowledged",
            State::Muted => "Muted",
            State::All => "Every state",
        }
    }

    fn parse(s: &str) -> Option<State> {
        State::ALL.into_iter().find(|v| v.name() == s)
    }

    /// The stored states of the rows it shows.
    fn stored(self) -> &'static [Stored] {
        match self {
            State::New => &[Stored::New],
            State::Acknowledged => &[Stored::Acknowledged],
            State::Muted | State::All => &Stored::ALL,
        }
    }

    fn admits(self, triage: Triage, muted: bool) -> bool {
        match self {
            State::New => triage == Triage::New && !muted,
            State::Acknowledged => triage == Triage::Acknowledged && !muted,
            State::Muted => muted,
            State::All => true,
        }
    }
}

/// How a row stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Triage {
    New,
    Acknowledged,
}

impl Triage {
    fn of(row: &BlockedRow) -> Triage {
        if row.is_new() {
            Triage::New
        } else {
            Triage::Acknowledged
        }
    }
}

impl Filter {
    /// `/egress[?view=…&state=…&project=…&layer=…&phase=…&job=…]`. A value that cannot be one
    /// is ignored.
    fn of(query: Option<&str>) -> Filter {
        let query = decode_form(query.unwrap_or("").as_bytes());
        let pick = |name: &str, from: &[&'static str]| {
            field(&query, name).and_then(|v| from.iter().copied().find(|k| *k == v))
        };
        let phases: Vec<&'static str> = PHASES.iter().map(|(k, _)| *k).collect();
        Filter {
            view: field(&query, "view").and_then(View::parse),
            subject: field(&query, "project").and_then(Subject::parse),
            layer: pick("layer", &LAYERS),
            phase: pick("phase", &phases),
            job: field(&query, "job")
                .filter(|j| vk_hub_proto::valid_id(j))
                .map(str::to_string),
            state: field(&query, "state")
                .and_then(State::parse)
                .unwrap_or_default(),
        }
    }

    fn view(&self) -> View {
        self.view.unwrap_or(View::Blocked)
    }

    /// Whether it shows `row`, of `id`, whatever its view, `muted` or not; `job_rows` are the
    /// rows the job it names shares, if it names one.
    fn admits(
        &self,
        id: &str,
        row: &BlockedRow,
        triage: Triage,
        muted: bool,
        job_rows: Option<&BTreeSet<String>>,
    ) -> bool {
        self.state.admits(triage, muted)
            && self.subject.as_ref().is_none_or(|s| *s == row.subject)
            && self.layer.is_none_or(|l| row.layers.contains_key(l))
            && self.phase.is_none_or(|p| row.phases.contains_key(p))
            && job_rows.is_none_or(|rows| rows.contains(id))
    }

    /// `/egress` with this filter, and `view` instead of its own, as an attribute's value.
    fn href(&self, view: View) -> String {
        let subject = self.subject.as_ref().map(Subject::param);
        let fields = [
            ("view", (view != View::Blocked).then_some(view.name())),
            ("state", Some(self.state.name()).filter(|s| !s.is_empty())),
            ("project", subject.as_deref()),
            ("layer", self.layer),
            ("phase", self.phase),
            ("job", self.job.as_deref()),
        ];
        let mut out = PATH.to_string();
        let mut separator = '?';
        for (name, value) in fields {
            if let Some(value) = value {
                out.push(separator);
                out.push_str(name);
                out.push('=');
                out.push_str(&percent_encode(value));
                separator = '&';
            }
        }
        out
    }
}

/// `/egress?state=all&project=<subject>`: every row of `subject`, as an attribute's value.
pub(super) fn subject_href(subject: &Subject) -> String {
    Filter {
        subject: Some(subject.clone()),
        state: State::All,
        ..Filter::default()
    }
    .href(View::Blocked)
}

/// What the page shows.
struct Listing {
    /// The view's rows the filter admits, the latest first: at most [`PAGE_ROWS`].
    shown: Vec<(String, BlockedRow)>,
    /// Whether more follow them.
    more: bool,
    /// Whether rows were left unread for [`ROW_BUDGET`] before the page filled.
    cut: bool,
    /// Each view's count under the filter, in [`View::ALL`]'s order.
    counts: Vec<(View, Count)>,
    /// Whether any row is kept.
    any: bool,
    /// The filter's job, when it is kept.
    job: Option<JobRow>,
    /// Nodes taking placed jobs that do not announce egress reports, by ID and name.
    unreported: Vec<(String, String)>,
    /// The mutes in force, by subject.
    mutes: HashMap<String, Mute>,
    /// The rows read from the indexes.
    #[cfg(test)]
    read: usize,
}

/// A view's count under a filter: at least `n` when `partial`, its rows not all read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Count {
    n: u64,
    partial: bool,
}

/// The nodes that take placed jobs and do not announce egress reports: their jobs send none,
/// so nothing of theirs is listed.
fn unreported(hub: &Hub) -> Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = hub
        .db
        .nodes()?
        .into_iter()
        .filter(|(_, n)| {
            !n.pools.is_empty() && n.inventory.as_ref().is_some_and(|i| !i.egress_reports)
        })
        .map(|(id, n)| (id, n.hostname))
        .collect();
    out.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
    Ok(out)
}

/// What the page shows for `filter`, reading at most [`ROW_BUDGET`] rows: those of the view
/// and state it asks for, from the indexes, the latest first ([`Db::egress_scan`]); a job's by
/// their IDs. A view's count is read from the counts kept when nothing but the state and the
/// project narrows it, else counted within the budget.
///
/// [`Db::egress_scan`]: crate::store::Db::egress_scan
fn listing(hub: &Hub, filter: &Filter) -> Result<Listing> {
    let now = crate::now_secs();
    let mutes = hub.db.egress_mutes(now)?;
    let job = match &filter.job {
        Some(id) => hub.db.job(id)?,
        None => None,
    };
    let totals = hub.db.egress_counts(None)?;
    let any = totals.values().any(|n| *n > 0);
    let admits = |id: &str, row: &BlockedRow| {
        let muted = mutes.contains_key(&row.subject.param());
        filter.admits(id, row, Triage::of(row), muted, None)
    };
    let view = filter.view();
    let mut l = Listing {
        shown: Vec::new(),
        more: false,
        cut: false,
        counts: Vec::new(),
        any,
        job: None,
        unreported: unreported(hub)?,
        mutes: HashMap::new(),
        #[cfg(test)]
        read: 0,
    };
    if filter.job.is_some() {
        // A job's rows, few as its report: read by ID, and counted exactly.
        let ids: Vec<String> = job
            .as_ref()
            .map(|j| shares(j).into_keys().collect())
            .unwrap_or_default();
        let ids: Vec<&String> = ids.iter().collect();
        let mut rows: Vec<(String, BlockedRow)> = hub
            .db
            .egress_rows_of(&ids)?
            .into_iter()
            .filter(|(id, row)| admits(id, row))
            .collect();
        rows.sort_by(|a, b| b.1.latest_at.cmp(&a.1.latest_at).then(a.0.cmp(&b.0)));
        for v in View::ALL {
            let n = rows.iter().filter(|(_, r)| r.finding.view() == v).count();
            let n = u64::try_from(n).unwrap_or(u64::MAX);
            l.counts.push((v, Count { n, partial: false }));
        }
        rows.retain(|(_, r)| r.finding.view() == view);
        l.more = rows.len() > PAGE_ROWS;
        rows.truncate(PAGE_ROWS);
        l.shown = rows;
    } else {
        let subject = filter.subject.as_ref().map(Subject::param);
        let mut subjects: Vec<Option<&str>> = match (filter.state, &subject) {
            (State::Muted, Some(s)) => vec![Some(s.as_str())],
            (State::Muted, None) => mutes.keys().map(|m| Some(m.as_str())).collect(),
            (_, s) => vec![s.as_deref()],
        };
        if filter.state == State::Muted {
            subjects.retain(|s| s.is_some_and(|s| mutes.contains_key(s)));
        }
        let ranges = |v: View| -> Vec<RowRange> {
            let mut out = Vec::new();
            for subject in &subjects {
                for stored in filter.state.stored() {
                    out.push(RowRange {
                        view: v,
                        stored: *stored,
                        subject: *subject,
                    });
                }
            }
            out
        };
        let mut budget = ROW_BUDGET;
        let mut shown = Vec::new();
        l.cut = hub.db.egress_scan(&ranges(view), &mut budget, |id, row| {
            if !admits(id, &row) {
                return ControlFlow::Continue(());
            }
            if shown.len() >= PAGE_ROWS {
                l.more = true;
                return ControlFlow::Break(());
            }
            shown.push((id.to_string(), row));
            ControlFlow::Continue(())
        })?;
        l.shown = shown;
        // Kept counts say how many rows each state holds, by subject: they answer a filter with
        // no layer or phase.
        let kept = filter.layer.is_none() && filter.phase.is_none();
        // The counts the shown subjects add, and those the muted take from every subject's.
        let (mut added, mut taken) = (Vec::new(), Vec::new());
        if kept {
            for s in &subjects {
                added.push(match s {
                    None => totals.clone(),
                    Some(s) => hub.db.egress_counts(Some(s))?,
                });
            }
            // A state but Muted's and All's leaves the muted out.
            if subject.is_none() && !matches!(filter.state, State::Muted | State::All) {
                for m in mutes.keys() {
                    taken.push(hub.db.egress_counts(Some(m))?);
                }
            }
        }
        let muted_subject = subject.as_ref().is_some_and(|s| mutes.contains_key(s));
        for v in View::ALL {
            let sum = |counts: &[HashMap<(View, Stored), u64>]| -> u64 {
                let stored = filter.state.stored();
                (counts.iter())
                    .flat_map(|c| stored.iter().filter_map(move |st| c.get(&(v, *st))))
                    .fold(0, |sum, n| sum.saturating_add(*n))
            };
            let count = if kept {
                let n = match (muted_subject, filter.state) {
                    (true, State::New | State::Acknowledged) => 0,
                    _ => sum(&added).saturating_sub(sum(&taken)),
                };
                Count { n, partial: false }
            } else if v == view && !l.more {
                // The page's scan read them all, or as many as the budget let it.
                let n = u64::try_from(l.shown.len()).unwrap_or(u64::MAX);
                Count { n, partial: l.cut }
            } else {
                let mut n = 0u64;
                let partial = hub.db.egress_scan(&ranges(v), &mut budget, |id, row| {
                    if admits(id, &row) {
                        n = n.saturating_add(1);
                    }
                    ControlFlow::Continue(())
                })?;
                // Never fewer than the page found, one past those it shows.
                if v == view {
                    let found = u64::try_from(l.shown.len()).unwrap_or(u64::MAX);
                    n = n.max(found.saturating_add(1));
                }
                Count { n, partial }
            };
            l.counts.push((v, count));
        }
        #[cfg(test)]
        {
            l.read = ROW_BUDGET - budget;
        }
    }
    l.job = job;
    l.mutes = mutes;
    Ok(l)
}

/// What `/events/egress[?…]` streams: the rows of the filter in `query` ([`Filter::of`]), with
/// the views' counts, as the jobs' reports and the rows' triage change.
pub(super) fn source(hub: &Arc<Hub>, caches: &Arc<Caches>, query: Option<&str>) -> Source {
    if let Some(q) = observed::Query::of(query) {
        return observed::source(hub, q);
    }
    let filter = Filter::of(query);
    let changes = hub.subscribe_egress();
    let (hub, caches) = (hub.clone(), caches.clone());
    Source::Own {
        name: EVENT,
        changes,
        render: Arc::new(move || {
            Ok(caches
                .blocked
                .render(&hub, &filter, Instant::now())?
                .as_ref()
                .clone())
        }),
    }
}

/// `GET /egress[?…]` ([`Filter::of`]).
pub(super) async fn get(
    query: Option<&str>,
    auth: &Auth,
    caches: &Arc<Caches>,
    ui: &Ui,
) -> Result<Response<Body>> {
    if let Some(q) = observed::Query::of(query) {
        return observed::get(q, auth, ui).await;
    }
    if let Some(q) = rules::Query::of(query) {
        return rules::get(q, auth, caches, ui).await;
    }
    let filter = Filter::of(query);
    let (hub, wanted) = (ui.hub.clone(), filter.clone());
    let (listing, subjects) =
        blocking(move || Ok((listing(&hub, &wanted)?, hub.db.egress_subjects()?))).await?;
    let main = listing_page(&filter, &listing, &subjects, auth);
    Ok(page(fleet::layout("Egress", PATH, auth, &main)))
}

fn listing_page(filter: &Filter, l: &Listing, subjects: &[(String, String)], auth: &Auth) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    tabs(&mut h, Tab::Blocked, filter.subject.as_ref());
    unreported_callout(&mut h, &l.unreported);
    h.raw("<p class=\"sub\">What the jobs of the history were refused, by destination and ")
        .raw("project, as their nodes reported it.</p>");
    mutes_note(&mut h, &l.mutes, auth);
    filter_form(&mut h, filter, subjects);
    // Replaced whole by the filter's form, live part and all, so the old stream closes and the
    // new filter's opens.
    h.raw("<div id=\"")
        .raw(RESULTS)
        .raw("\"><div hx-ext=\"sse\" sse-connect=\"/events/")
        .raw(EVENT)
        .text(
            filter
                .href(filter.view())
                .strip_prefix(PATH)
                .unwrap_or_default(),
        )
        .raw("\" sse-swap=\"")
        .raw(EVENT)
        .raw("\" sse-close=\"close\">");
    results(&mut h, filter, l);
    h.raw("</div></div>");
    h
}

/// The part of the page that follows the rows: the filter's job, the views with their counts,
/// and the view's rows. No form: a choice being made is never reset by an update.
fn results(h: &mut Html, filter: &Filter, l: &Listing) {
    if let Some(id) = &filter.job {
        job_chip(h, filter, id, l.job.as_ref());
    }
    let view = filter.view();
    h.raw("<nav class=\"tabs\" aria-label=\"Egress views\">");
    for (v, count) in &l.counts {
        h.raw("<a href=\"")
            .text(filter.href(*v))
            .raw("\"")
            .raw(if *v == view {
                " aria-current=\"page\""
            } else {
                ""
            })
            .raw(">")
            .raw(v.label())
            .raw(" (")
            .text(count.n)
            .raw(if count.partial { "+" } else { "" })
            .raw(")</a>");
    }
    h.raw("</nav>");
    h.raw("<p class=\"sub\">").raw(match view {
        View::Blocked => {
            "The switch blocked these attempts. Their effect on the jobs' results is unknown."
        }
        View::WouldBlock => {
            "A dry-run allowlist would have blocked these attempts; the switch carried them."
        }
        View::Refused => {
            "Each of these declarations was found at validation, before its job's script ran: \
             nothing was attempted. An invalid one failed its job; one outside a layer above did \
             not, and that layer refuses what it lists when the job runs."
        }
    });
    h.raw("</p>");
    if l.shown.is_empty() {
        h.raw(match (l.any, l.cut) {
            (false, _) => "<p class=\"empty\">nothing refused yet</p>",
            (true, true) => {
                "<p class=\"empty\" role=\"status\">none among the latest rows read: narrow \
                 the filter to see older ones</p>"
            }
            (true, false) => "<p class=\"empty\" role=\"status\">none match</p>",
        });
        return;
    }
    rows_table(h, filter, &l.shown, &l.mutes);
    let count = l.counts.iter().find(|(v, _)| *v == view).map(|(_, c)| *c);
    let shown = u64::try_from(l.shown.len()).unwrap_or(u64::MAX);
    match count {
        Some(c) if !c.partial && c.n > shown => {
            h.raw("<p class=\"sub\">")
                .text(c.n - shown)
                .raw(" more, older: narrow the filter to see them.</p>");
        }
        _ if l.more => {
            h.raw("<p class=\"sub\">More, older: narrow the filter to see them.</p>");
        }
        _ if l.cut => {
            h.raw("<p class=\"sub\">Only the latest rows were read: narrow the filter to see ")
                .raw("older ones.</p>");
        }
        _ => {}
    }
}

/// The page's tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Blocked,
    Observed,
    Rules,
}

/// The page's tabs, `here` the current one; Blocked's and Observed traffic's for `subject` when
/// one is chosen.
fn tabs(h: &mut Html, here: Tab, subject: Option<&Subject>) {
    let blocked_href = match subject {
        Some(s) => Filter {
            subject: Some(s.clone()),
            ..Filter::default()
        }
        .href(View::Blocked),
        None => PATH.to_string(),
    };
    let observed_href = match subject {
        Some(s) => observed::subject_href(s),
        None => format!("{PATH}?tab=observed"),
    };
    h.raw("<nav class=\"tabs\" aria-label=\"Egress tabs\">");
    for (href, label, tab) in [
        (blocked_href, "Blocked", Tab::Blocked),
        (observed_href, "Observed traffic", Tab::Observed),
        (rules::PATH.to_string(), "Rules", Tab::Rules),
    ] {
        h.raw("<a href=\"")
            .text(href)
            .raw("\"")
            .raw(if tab == here {
                " aria-current=\"page\""
            } else {
                ""
            })
            .raw(">")
            .raw(label)
            .raw("</a>");
    }
    h.raw("</nav>");
}

/// The nodes whose jobs cannot appear here, when there are any.
fn unreported_callout(h: &mut Html, nodes: &[(String, String)]) {
    if nodes.is_empty() {
        return;
    }
    h.raw("<p class=\"callout warn\">Reporting unavailable on ");
    for (i, (id, name)) in nodes.iter().enumerate() {
        if i > 0 {
            h.raw(", ");
        }
        h.raw("<a href=\"/node/")
            .text(id)
            .raw("\">")
            .node(name)
            .raw("</a>");
    }
    h.raw(match nodes.len() {
        1 => ": it does not announce egress reporting, so what its jobs",
        _ => ": they do not announce egress reporting, so what their jobs",
    })
    .raw(" were refused is not listed here. A newer <code>vk</code> reports it.</p>");
}

/// The mutes in force, each with its reason and end, when there are any: their rows are out of
/// the inbox and its count, shown under *Muted*. An operator unmutes each here too: a mute
/// outlives the rows it took out.
fn mutes_note(h: &mut Html, mutes: &HashMap<String, Mute>, auth: &Auth) {
    if mutes.is_empty() {
        return;
    }
    let mut mutes: Vec<(&String, &Mute)> = mutes.iter().collect();
    mutes.sort_by(|a, b| (&a.1.who, a.0).cmp(&(&b.1.who, b.0)));
    h.raw("<div class=\"callout\"><p>Muted, out of the inbox and its count, not out of the record:</p><ul>");
    for (subject, m) in &mutes {
        h.raw("<li>");
        let shown = Filter {
            subject: Subject::parse(subject),
            state: State::Muted,
            ..Filter::default()
        };
        h.raw("<a href=\"")
            .text(shown.href(View::Blocked))
            .raw("\">")
            .node(&m.who)
            .raw("</a> ");
        until(h, m);
        h.raw(" (").node(&m.reason).raw(")");
        if auth.session.role >= Role::Operator {
            h.raw(" <form class=\"steer\" method=\"post\" action=\"")
                .raw(ACTION_PATH)
                .raw("\">");
            pages::csrf_field(h, auth);
            h.raw("<input type=\"hidden\" name=\"op\" value=\"unmute\">")
                .raw("<input type=\"hidden\" name=\"subject\" value=\"")
                .text(subject)
                .raw("\"><button>Unmute</button></form>");
        }
        h.raw("</li>");
    }
    h.raw("</ul></div>");
}

/// When mute `m` ends: `until 2026-…`, or `until unmuted`.
fn until(h: &mut Html, m: &Mute) {
    match m.until {
        Some(t) => {
            h.raw("until ");
            pages::time(h, t, &pages::started(t));
        }
        None => {
            h.raw("until unmuted");
        }
    }
}

/// The filter's job, as a chip whose link drops it.
fn job_chip(h: &mut Html, filter: &Filter, id: &str, job: Option<&JobRow>) {
    h.raw("<p><span class=\"badge\">Job ");
    match job {
        Some(j) => h
            .raw("<a href=\"")
            .raw(super::jobs::DETAIL_PREFIX)
            .text(id)
            .raw("\">")
            .node(j.name.as_deref().unwrap_or(&j.title))
            .raw("</a>"),
        None => h.text(id.get(..8).unwrap_or(id)).raw(", no longer kept"),
    };
    let every_job = Filter {
        job: None,
        ..filter.clone()
    };
    h.raw(" <a href=\"")
        .text(every_job.href(filter.view()))
        .raw("\" title=\"Every job's\" aria-label=\"Every job's\">×</a></span></p>");
}

/// The filter's form: state, project, layer and phase, the view and job kept. As on the audit log,
/// with htmx a choice applies at once, the rows swapped in and the URL updated.
fn filter_form(h: &mut Html, filter: &Filter, subjects: &[(String, String)]) {
    h.raw("<form id=\"egress-filter\" class=\"filter\" method=\"get\" action=\"")
        .raw(PATH)
        .raw("\" hx-get=\"")
        .raw(PATH)
        .raw("\" hx-trigger=\"submit, change from:(#egress-filter select)\" hx-target=\"#")
        .raw(RESULTS)
        .raw("\" hx-select=\"#")
        .raw(RESULTS)
        .raw("\" hx-swap=\"outerHTML\" hx-push-url=\"true\" hx-sync=\"this:replace\">");
    if let Some(view) = filter.view.filter(|v| *v != View::Blocked) {
        h.raw("<input type=\"hidden\" name=\"view\" value=\"")
            .raw(view.name())
            .raw("\">");
    }
    if let Some(job) = &filter.job {
        h.raw("<input type=\"hidden\" name=\"job\" value=\"")
            .text(job)
            .raw("\">");
    }
    h.raw("<select name=\"state\" aria-label=\"State\">");
    for state in State::ALL {
        h.raw("<option value=\"").raw(state.name()).raw("\"");
        if filter.state == state {
            h.raw(" selected");
        }
        h.raw(">").raw(state.label()).raw("</option>");
    }
    h.raw("</select>");
    // Each subject once, in the words of one of its rows.
    let mut subjects: BTreeMap<String, String> = subjects.iter().cloned().collect();
    if let Some(s) = &filter.subject {
        subjects.entry(s.param()).or_insert_with(|| s.param());
    }
    let mut subjects: Vec<(String, String)> = subjects.into_iter().collect();
    subjects.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
    let chosen = filter.subject.as_ref().map(Subject::param);
    h.raw("<select name=\"project\" aria-label=\"Project\">")
        .raw("<option value=\"\">Every project</option>");
    for (param, who) in &subjects {
        h.raw("<option value=\"").text(param).raw("\"");
        if chosen.as_ref() == Some(param) {
            h.raw(" selected");
        }
        h.raw(">").node(who).raw("</option>");
    }
    h.raw("</select><select name=\"layer\" aria-label=\"Decided by\">")
        .raw("<option value=\"\">Every layer</option>");
    for layer in LAYERS {
        h.raw("<option value=\"").raw(layer).raw("\"");
        if filter.layer == Some(layer) {
            h.raw(" selected");
        }
        h.raw(">")
            .text(capital(layer_label(layer)))
            .raw("</option>");
    }
    h.raw("</select><select name=\"phase\" aria-label=\"Phase\">")
        .raw("<option value=\"\">Every phase</option>");
    for (phase, label) in PHASES {
        h.raw("<option value=\"").raw(phase).raw("\"");
        if filter.phase == Some(phase) {
            h.raw(" selected");
        }
        h.raw(">").raw(label).raw("</option>");
    }
    h.raw("</select> <button>Show</button></form>");
}

/// The rows of `view`, the latest first.
fn rows_table(
    h: &mut Html,
    filter: &Filter,
    rows: &[(String, BlockedRow)],
    mutes: &HashMap<String, Mute>,
) {
    let view = filter.view();
    let refused = view == View::Refused;
    h.raw("<table class=\"grid\"><thead><tr><th>")
        .raw(if refused {
            "declaration"
        } else {
            "destination"
        })
        .raw("</th><th>project</th><th class=\"num\">jobs</th>");
    if !refused {
        h.raw("<th class=\"num\">attempts</th>");
    }
    h.raw("<th>latest</th><th>")
        .raw(if refused { "outside" } else { "blocked by" })
        .raw("</th><th>state</th></tr></thead><tbody>");
    for (id, row) in rows {
        h.raw("<tr><td><a href=\"")
            .raw(ROW_PREFIX)
            .text(id)
            .raw("\"><code>")
            .node(&row.finding.text())
            .raw("</code></a></td><td><a href=\"")
            .text(
                Filter {
                    subject: Some(row.subject.clone()),
                    ..filter.clone()
                }
                .href(view),
            )
            .raw("\">")
            .node(&row.who())
            .raw("</a></td><td class=\"num\">")
            .text(row.jobs)
            .raw("</td>");
        if !refused {
            h.raw("<td class=\"num\">").text(row.attempts).raw("</td>");
        }
        h.raw("<td>");
        pages::at(h, row.latest_at);
        h.raw("</td><td>").text(layers_text(row)).raw("</td><td>");
        state_badge(h, row, Triage::of(row), mutes.get(&row.subject.param()));
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

/// The layers that decided a row, most jobs first: `the node's cap`, `the job's narrowing (2
/// jobs), the node's cap (1 job)` when more than one did.
fn layers_text(row: &BlockedRow) -> String {
    let mut layers: Vec<(&String, &u64)> = row.layers.iter().collect();
    layers.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    if let [(layer, _)] = layers.as_slice() {
        return layer_label(layer).to_string();
    }
    let parts: Vec<String> = layers
        .iter()
        .map(|(layer, n)| {
            let plural = if **n == 1 { "" } else { "s" };
            format!("{} ({n} job{plural})", layer_label(layer))
        })
        .collect();
    parts.join(", ")
}

/// How a row stands, and whether its subject is `muted`, the mute's reason on hover.
fn state_badge(h: &mut Html, row: &BlockedRow, triage: Triage, muted: Option<&Mute>) {
    let by = row.acknowledged.as_ref().map(|a| &a.by);
    match (triage, by) {
        (Triage::New, _) | (_, None) => {
            h.raw("<span class=\"badge bad\">New</span>");
        }
        (Triage::Acknowledged, Some(by)) => {
            h.raw("<span class=\"badge\" title=\"By ")
                .text(by)
                .raw("\">Acknowledged</span>");
        }
    }
    if let Some(m) = muted {
        h.raw(" <span class=\"badge\" title=\"")
            .text(&m.reason)
            .raw("\">Muted</span>");
    }
}

/// `/egress/rows/<id>`'s row, if `path` is that for a well-formed ID.
pub(super) fn row_target(path: &str) -> Option<&str> {
    path.strip_prefix(ROW_PREFIX)
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// What a row's page shows.
struct RowDetail {
    row: BlockedRow,
    /// Its latest jobs: each one's ID, when it ended, its attempts and its record if kept.
    jobs: Vec<(String, u64, u64, Option<JobRow>)>,
    names: HashMap<String, String>,
    /// Its subject's mute in force.
    mute: Option<Mute>,
}

/// `GET /egress/rows/<id>`.
pub(super) async fn row(id: &str, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let (hub, wanted) = (ui.hub.clone(), id.to_string());
    let detail = blocking(move || {
        let Some(row) = hub.db.egress_row(&wanted)? else {
            return anyhow::Ok(None);
        };
        let mut jobs = Vec::new();
        for (job, at, attempts) in hub.db.egress_row_jobs(&wanted, ROW_JOBS)? {
            let record = hub.db.job(&job)?;
            jobs.push((job, at, attempts, record));
        }
        let names = hub.db.node_names()?.into_iter().collect();
        let mute = hub
            .db
            .egress_mutes(crate::now_secs())?
            .remove(&row.subject.param());
        Ok(Some(RowDetail {
            row,
            jobs,
            names,
            mute,
        }))
    })
    .await?;
    let Some(detail) = detail else {
        return Ok(message(
            StatusCode::NOT_FOUND,
            "There is no such row: no job of the history shares it.",
        ));
    };
    let main = row_page(id, &detail, auth);
    Ok(page(fleet::layout("Egress", PATH, auth, &main)))
}

/// What one of a row's jobs reported of it: the denials of its destination, or the refusals
/// of its declaration.
enum Evidence<'a> {
    Denials(Vec<&'a EgressEntry>),
    Refusals(Vec<&'a EgressRefusal>),
}

fn evidence<'a>(finding: &Finding, j: &'a JobRow) -> Evidence<'a> {
    let report = egress::report(j);
    let entries = report.map(|r| r.entries.as_slice()).unwrap_or_default();
    let refusals = report.map(|r| r.refusals.as_slice()).unwrap_or_default();
    match finding {
        Finding::Denial { .. } => Evidence::Denials(
            entries
                .iter()
                .filter(|e| Finding::denial(e).as_ref() == Some(finding))
                .collect(),
        ),
        Finding::Refusal { .. } => Evidence::Refusals(
            refusals
                .iter()
                .filter(|r| Finding::refusal(r) == *finding)
                .collect(),
        ),
    }
}

fn row_page(id: &str, d: &RowDetail, auth: &Auth) -> Html {
    let row = &d.row;
    let view = row.finding.view();
    let mut h = Html::new();
    h.raw("<h1><code>")
        .node(&row.finding.text())
        .raw("</code></h1><p class=\"sub\">")
        .raw(view.label())
        .raw(" · <a href=\"")
        .text(subject_href(&row.subject))
        .raw("\">")
        .node(&row.who())
        .raw("</a> · <a href=\"")
        .text(observed::subject_href(&row.subject))
        .raw("\">Its observed traffic</a> · <a href=\"")
        .raw(PATH)
        .raw("\">All of Egress</a></p>");
    // Its jobs' records, as kept, with what each reported of it.
    let kept: Vec<(&JobRow, Evidence)> = d
        .jobs
        .iter()
        .filter_map(|(_, _, _, j)| j.as_ref())
        .map(|j| (j, evidence(&row.finding, j)))
        .collect();

    h.raw("<section><h2>Summary</h2><table class=\"kv\"><tbody>");
    pages::kv_html(&mut h, "State", &{
        let mut b = Html::new();
        state_badge(&mut b, row, Triage::of(row), d.mute.as_ref());
        b
    });
    pages::kv(&mut h, "Jobs", &format!("{} in the history", row.jobs));
    if view != View::Refused {
        pages::kv(&mut h, "Attempts", &row.attempts.to_string());
    }
    pages::kv_html(&mut h, "Latest", &pages::at_html(row.latest_at));
    pages::kv(
        &mut h,
        if view == View::Refused {
            "Outside"
        } else {
            "Blocked by"
        },
        &layers_text(row),
    );
    let phases: Vec<&str> = PHASES
        .iter()
        .filter(|(k, _)| row.phases.contains_key(*k))
        .map(|(_, label)| *label)
        .collect();
    pages::kv(&mut h, "Phases", &phases.join(", "));
    let mut vms = BTreeSet::new();
    let mut refs = BTreeSet::new();
    for (j, ev) in &kept {
        match ev {
            Evidence::Denials(es) => vms.extend(es.iter().map(|e| egress::vm_text(&e.source))),
            Evidence::Refusals(rs) => vms.extend(rs.iter().map(|r| egress::vm_text(&r.source))),
        }
        if let Some(r) = &j.git_ref {
            refs.insert((r.clone(), j.protected));
        }
    }
    let vms: Vec<String> = vms.into_iter().collect();
    pages::kv_node(&mut h, "VMs", &vms.join(", "));
    let refs: Vec<String> = refs
        .into_iter()
        .map(|(r, protected)| match protected {
            Some(true) => format!("{r} (protected)"),
            Some(false) => format!("{r} (unprotected)"),
            None => format!("{r} (protection not reported)"),
        })
        .collect();
    pages::kv_node(&mut h, "Refs", &refs.join(", "));
    h.raw("</tbody></table><p class=\"sub\">VMs and refs of its latest ")
        .text(kept.len())
        .raw(" jobs kept; protection as GitLab reported it.</p></section>");

    triage(&mut h, id, d, auth);
    what_to_change(&mut h, &kept, &d.names);
    row_jobs(&mut h, view, d);
    h
}

/// Where to look to allow it, by the layer that decided it in each of the jobs `kept`: the
/// node and its key, or the job's or a service's variable; for a hub rule or a layer the node
/// could not tell, the evidence alone.
fn what_to_change(h: &mut Html, kept: &[(&JobRow, Evidence)], names: &HashMap<String, String>) {
    // Each distinct place to look, with the nodes it is on for a node's key.
    let mut checks: Vec<(Check, BTreeSet<Option<String>>)> = Vec::new();
    for (j, ev) in kept {
        let node = j
            .node
            .as_ref()
            .map(|n| names.get(n).cloned().unwrap_or_else(|| n.clone()));
        let found: Vec<Check> = match ev {
            Evidence::Denials(es) => {
                let ran = egress::report(j).map(|r| r.hub_rules.as_slice());
                es.iter()
                    .map(|e| egress::denial_check(e, ran.unwrap_or_default()))
                    .collect()
            }
            Evidence::Refusals(rs) => rs.iter().flat_map(|r| egress::refusal_checks(r)).collect(),
        };
        for c in found {
            let on = matches!(c, Check::Node(_)).then(|| node.clone()).flatten();
            match checks.iter_mut().find(|(have, _)| *have == c) {
                Some((_, nodes)) => {
                    nodes.insert(on);
                }
                None => checks.push((c, BTreeSet::from([on]))),
            }
        }
    }
    h.raw("<section><h2>What to change</h2>");
    if checks.is_empty() {
        h.raw("<p>Nothing to point at: the evidence below is all there is.</p></section>");
        return;
    }
    h.raw("<ul class=\"access\">");
    for (c, nodes) in &checks {
        h.raw("<li>");
        match c {
            Check::Node(key) => {
                h.raw("<code>").text(key).raw("</code> on ");
                let named: Vec<&String> = nodes.iter().flatten().collect();
                if named.is_empty() {
                    h.raw("their node");
                } else {
                    h.raw(if named.len() == 1 { "node " } else { "nodes " });
                    for (i, n) in named.iter().enumerate() {
                        if i > 0 {
                            h.raw(", ");
                        }
                        h.node(n);
                    }
                }
            }
            Check::Variable { service, variable } => {
                if let Some(s) = service {
                    h.raw("service ").node(s).raw("'s ");
                }
                h.raw("<code>")
                    .text(variable)
                    .raw("</code>: change this job's CI configuration");
            }
            Check::HubRules { .. } => {
                h.text(capital(&c.text()))
                    .raw(": <code>vk-hub egress</code> shows and changes them; the evidence ")
                    .raw("below is what they refused");
            }
            Check::Nothing(why) => {
                h.text(capital(why))
                    .raw(": the evidence below is all there is");
            }
        }
        h.raw("</li>");
    }
    h.raw("</ul><p class=\"sub\">From its latest jobs kept. Changing one layer may not be ")
        .raw("enough: another may refuse it too.</p></section>");
}

/// `s` with its first letter capitalized.
fn capital(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// The latest jobs sharing the row, with how each ended.
fn row_jobs(h: &mut Html, view: View, d: &RowDetail) {
    h.raw("<section><h2>Latest jobs</h2><p class=\"sub\">")
        .raw(if view == View::Refused {
            "An invalid declaration failed each of them; one outside a layer above did not."
        } else {
            "Each job's result is shown as it ended; the denial's effect on it is unknown."
        })
        .raw("</p><table class=\"grid\"><thead><tr><th>job</th><th>ended</th><th>ref</th>")
        .raw("<th>node</th><th>");
    if view != View::Refused {
        h.raw("attempts</th><th>");
    }
    h.raw("result</th></tr></thead><tbody>");
    for (job, at, attempts, record) in &d.jobs {
        h.raw("<tr><td>");
        match record {
            Some(j) => {
                h.raw("<a href=\"")
                    .raw(super::jobs::DETAIL_PREFIX)
                    .text(job)
                    .raw("\">")
                    .node(j.name.as_deref().unwrap_or(&j.title))
                    .raw("</a>");
            }
            None => {
                h.text(job.get(..8).unwrap_or(job));
            }
        }
        h.raw("</td><td>");
        pages::at(h, *at);
        h.raw("</td><td>");
        match record.as_ref().and_then(|j| j.git_ref.as_deref()) {
            Some(r) => h.node(r),
            None => h.raw("-"),
        };
        h.raw("</td><td>");
        match record.as_ref().and_then(|j| j.node.as_deref()) {
            Some(n) => {
                h.raw("<a href=\"/node/")
                    .text(n)
                    .raw("\">")
                    .node(d.names.get(n).map_or(n, String::as_str))
                    .raw("</a>");
            }
            None => {
                h.raw("-");
            }
        }
        h.raw("</td>");
        if view != View::Refused {
            h.raw("<td class=\"num\">").text(attempts).raw("</td>");
        }
        h.raw("<td>");
        match record {
            Some(j) => super::jobs::result_badge(h, j),
            None => {
                h.raw("<span class=\"sub\">no longer kept</span>");
            }
        }
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table>");
    if d.row.jobs > u64::try_from(d.jobs.len()).unwrap_or(u64::MAX) {
        h.raw("<p class=\"sub\">The latest ")
            .text(d.jobs.len())
            .raw(" of ")
            .text(d.row.jobs)
            .raw(".</p>");
    }
    h.raw("</section>");
}

/// Where a row's page posts its triage and its subject's mute.
pub(super) const ACTION_PATH: &str = "/egress/action";

/// How long a mute lasts, as the form offers it: the field's value, in days, or for good.
const MUTE_FOR: [(&str, Option<u64>, &str); 3] = [
    ("7", Some(7), "7 days"),
    ("30", Some(30), "30 days"),
    ("never", None, "Indefinitely"),
];

/// How the row stands and who triaged it, its subject's mute, and for an operator the forms
/// that acknowledge or reopen it and mute or unmute its subject. Plain posts, back to the row.
fn triage(h: &mut Html, id: &str, d: &RowDetail, auth: &Auth) {
    let row = &d.row;
    let steer = auth.session.role >= Role::Operator;
    let what = if row.subject.is_project() {
        "project"
    } else {
        "key"
    };
    h.raw("<section><h2>Triage</h2><p>");
    match &row.acknowledged {
        Some(a) if !row.is_new() => {
            h.raw("Acknowledged by ").text(&a.by).raw(" ");
            pages::at(h, a.at);
            h.raw(".");
        }
        Some(a) => {
            h.raw("New again: acknowledged by ").text(&a.by).raw(" ");
            pages::at(h, a.at);
            h.raw(", and a job has added to it since.");
        }
        None => {
            h.raw("New: no one has acknowledged it.");
        }
    }
    if !row.is_new() {
        h.raw(" A job that adds to it makes it New again.");
    }
    h.raw("</p>");
    if steer {
        let (op, label) = if row.is_new() {
            ("acknowledge", "Acknowledge")
        } else {
            ("reopen", "Reopen")
        };
        action_form(h, id, auth, op);
        h.raw("<button>").raw(label).raw("</button></form>");
    }
    match &d.mute {
        Some(m) => {
            h.raw("<p>This ")
                .raw(what)
                .raw(" is muted by ")
                .text(&m.by)
                .raw(" ");
            until(h, m);
            h.raw(": ").node(&m.reason).raw(".</p>");
            if steer {
                action_form(h, id, auth, "unmute");
                h.raw("<button>Unmute</button></form>");
            }
        }
        None if steer => {
            action_form(h, id, auth, "mute");
            h.raw("<label>Reason <input type=\"text\" name=\"reason\" required maxlength=\"")
                .text(MAX_MUTE_REASON)
                .raw("\" autocomplete=\"off\"></label> <select name=\"for\" aria-label=\"For\">");
            for (value, _, label) in MUTE_FOR {
                h.raw("<option value=\"")
                    .raw(value)
                    .raw("\">")
                    .raw(label)
                    .raw("</option>");
            }
            h.raw("</select> <button>Mute this ")
                .raw(what)
                .raw("</button></form>");
        }
        None => {}
    }
    h.raw("<p class=\"sub\">A mute takes every row of this ")
        .raw(what)
        .raw(" out of the inbox and the navigation's count: they stay here under Muted, and on ")
        .raw("their jobs' pages.</p></section>");
}

/// Open a form posting `op` on row `id`, its button left to the caller.
fn action_form(h: &mut Html, id: &str, auth: &Auth, op: &'static str) {
    h.raw("<form class=\"steer\" method=\"post\" action=\"")
        .raw(ACTION_PATH)
        .raw("\">");
    pages::csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"row\" value=\"")
        .text(id)
        .raw("\"><input type=\"hidden\" name=\"op\" value=\"")
        .raw(op)
        .raw("\">");
}

/// What an operator's form asks of a row.
enum Act {
    Triage(bool),
    Mute { reason: String, until: Option<u64> },
    Unmute,
}

fn act(form: &[(String, String)], now: u64) -> Result<Act, &'static str> {
    Ok(match field(form, "op").unwrap_or("") {
        "acknowledge" => Act::Triage(true),
        "reopen" => Act::Triage(false),
        "unmute" => Act::Unmute,
        "mute" => {
            let reason = field(form, "reason").unwrap_or("").trim();
            if reason.is_empty() || reason.chars().count() > MAX_MUTE_REASON {
                return Err("Refused: a mute needs a reason, of at most 256 characters.");
            }
            let Some((_, days, _)) = MUTE_FOR
                .iter()
                .find(|(v, _, _)| Some(*v) == field(form, "for"))
            else {
                return Err("Refused: a mute lasts 7 days, 30 days or indefinitely.");
            };
            Act::Mute {
                reason: reason.to_string(),
                until: days.map(|d| now.saturating_add(d.saturating_mul(86_400))),
            }
        }
        _ => return Err("No such action."),
    })
}

/// `POST /egress/action`: an operator's triage of a row, or mute of its subject, as the
/// session's principal; audited by the store. Back to the row's page.
pub(super) async fn action(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(message(status, text)),
    };
    // A mute named by its subject, from the page's list of mutes: it outlives its rows.
    if field(&form, "op") == Some("unmute")
        && let Some(subject) = field(&form, "subject").and_then(Subject::parse)
    {
        let (hub, principal) = (ui.hub.clone(), auth.session.principal());
        blocking(move || {
            hub.db
                .egress_unmute(&subject, &principal, crate::now_secs())
        })
        .await?;
        ui.hub.egress_changed();
        return Ok(see_other(PATH));
    }
    let Some(id) = field(&form, "row")
        .filter(|id| vk_hub_proto::valid_id(id))
        .map(str::to_string)
    else {
        return Ok(message(StatusCode::BAD_REQUEST, "No such row."));
    };
    let now = crate::now_secs();
    let act = match act(&form, now) {
        Ok(act) => act,
        Err(why) => return Ok(message(StatusCode::BAD_REQUEST, why)),
    };
    let (hub, principal, row_id) = (ui.hub.clone(), auth.session.principal(), id.clone());
    let found = blocking(move || {
        // The subject muted is the row's, never one the form names.
        let Some(row) = hub.db.egress_row(&row_id)? else {
            return anyhow::Ok(false);
        };
        match act {
            Act::Triage(acknowledge) => {
                hub.db
                    .egress_triage(&row_id, acknowledge, &principal, now)?;
            }
            Act::Mute { reason, until } => {
                hub.db
                    .egress_mute(&row.subject, &row.who(), &reason, until, &principal, now)?;
            }
            Act::Unmute => {
                hub.db.egress_unmute(&row.subject, &principal, now)?;
            }
        }
        Ok(true)
    })
    .await?;
    if !found {
        return Ok(message(
            StatusCode::NOT_FOUND,
            "There is no such row: no job of the history shares it.",
        ));
    }
    ui.hub.egress_changed();
    Ok(see_other(&format!("{ROW_PREFIX}{id}")))
}

/// Back to `location`, one of this page's.
fn see_other(location: &str) -> Response<Body> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).unwrap_or(HeaderValue::from_static(PATH)),
    );
    resp
}

/// The row of `finding` of job `j`'s project, as an attribute's value.
pub(super) fn row_href(j: &JobRow, finding: &Finding) -> String {
    format!("{ROW_PREFIX}{}", row_id(&Subject::of(j), finding))
}

/// The rows job `id` shares in `view`, however they stand, as an attribute's value.
pub(super) fn job_href(id: &str, view: View) -> String {
    Filter {
        job: Some(id.to_string()),
        state: State::All,
        ..Filter::default()
    }
    .href(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::testing::{entry, job};
    use crate::store::Db;
    use vk_hub_proto::egress::{
        EgressDestination, EgressLayer, EgressOutcome, EgressProtocol, EgressReport,
    };

    /// Job `n`, ended refused `10.<n>:443` by its node's cap: a row of its own.
    fn refused(db: &Db, n: u64) {
        let id = format!("{n:032x}");
        let report = EgressReport {
            entries: vec![entry(
                EgressOutcome::Blocked,
                EgressProtocol::Tcp,
                EgressDestination::address(&format!("10.0.{}.{}:443", n / 256, n % 256)),
                Some(EgressLayer::NodeCap),
            )],
            ..EgressReport::default()
        };
        let row = job(n, report);
        let mut queued = row.clone();
        queued.result = None;
        queued.revision = 1;
        db.submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
            .unwrap();
        db.put_job(&id, &row, &[], 11).unwrap();
    }

    /// The inbox's page reads its rows from the indexes, one past those it shows, and its
    /// counts from those kept; a layer's filter counts within the budget.
    #[test]
    fn a_page_of_rows_reads_no_more_than_it_shows() {
        let db = Arc::new(Db::open_memory().unwrap());
        let hub = Hub::new(db.clone(), None);
        let rows = PAGE_ROWS as u64 + 50;
        for n in 1..=rows {
            refused(&db, n);
        }
        let l = listing(&hub, &Filter::default()).unwrap();
        assert_eq!(l.read, PAGE_ROWS + 1);
        assert_eq!(l.shown.len(), PAGE_ROWS);
        assert!(l.more && !l.cut);
        assert_eq!(
            l.shown.first().map(|(_, r)| r.latest_at),
            Some(1_000 + rows)
        );
        assert_eq!(
            l.counts.first(),
            Some(&(
                View::Blocked,
                Count {
                    n: rows,
                    partial: false
                }
            ))
        );
        let layer = Filter {
            layer: Some("node_cap"),
            ..Filter::default()
        };
        let l = listing(&hub, &layer).unwrap();
        // The page's, then the view's count: no more than the budget, the count no less than
        // the page found, and said to be partial.
        assert_eq!(l.read, ROW_BUDGET);
        assert_eq!(
            l.counts.first(),
            Some(&(
                View::Blocked,
                Count {
                    n: PAGE_ROWS as u64 + 1,
                    partial: true
                }
            ))
        );
        let mut h = Html::new();
        results(&mut h, &layer, &l);
        assert!(h.into_string().contains("Blocked (201+)"));
    }

    /// Streams of one filter share a rendering within the debounce past a change, and render
    /// again past it.
    #[test]
    fn streams_of_one_filter_share_its_rendering() {
        let db = Arc::new(Db::open_memory().unwrap());
        let hub = Hub::new(db.clone(), None);
        refused(&db, 1);
        let renders = Renders::default();
        let rendered = || renders.rendered.load(std::sync::atomic::Ordering::Relaxed);
        let start = Instant::now();
        let filter = Filter::default();
        let a = renders.render(&hub, &filter, start).unwrap();
        let b = renders.render(&hub, &filter, start).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(rendered(), 1);
        hub.egress_changed();
        renders.render(&hub, &filter, start).unwrap();
        assert_eq!(rendered(), 1);
        renders.render(&hub, &filter, start + SHARED).unwrap();
        assert_eq!(rendered(), 2);
        // Another filter renders its own.
        let all = Filter {
            state: State::All,
            ..Filter::default()
        };
        renders.render(&hub, &all, start + SHARED).unwrap();
        assert_eq!(rendered(), 3);
    }
}
