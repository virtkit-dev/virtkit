//! `/egress?tab=observed`: the Egress page's *Observed traffic* tab, for viewers and operators
//! alike — what the jobs of the history reached, from their nodes' reports
//! ([`crate::egress::observed`]): each project with how completely its jobs reported, and for
//! one project (`project=`) its destinations by phase, with their jobs, attempts, days, refs
//! and latest job, filtered by phase and protection, and whether the same destination was also
//! refused, on the Blocked tab, and how the rules as they stand now treat it, ref by ref
//! ([`crate::egress::rule_use::compare`]). The list of projects names the rules' entries no
//! contact matched in 30 days ([`crate::egress::rule_use`]). A destination is reached, or
//! carried while a dry-run allowlist would have refused it; a DNS entry is a lookup. The
//! listing follows the jobs' reports over
//! `/events/egress?tab=observed…`, as the Blocked tab's rows do; the filter's form stays out of
//! what is swapped.
//!
//! Destinations, refs and project names are the jobs' or their guests' to choose: each goes
//! through [`Html::node`].

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use hyper::Response;

use super::super::html::Html;
use super::super::jobs::percent_encode;
use super::super::sse::Source;
use super::super::{Auth, Body, Ui, blocking, decode_form, field, fleet, page};
use super::{Caches, EVENT, PAGE_ROWS, PATH, ROW_PREFIX, unreported, unreported_callout};
use crate::egress::aggregates::Aggregates;
use crate::egress::blocked::{Finding, PHASES, Subject, View, row_id};
use crate::egress::matching::Dest;
use crate::egress::observed::PROTECTIONS;
use crate::egress::rule_use::{self, Compared, RuleUse};
use crate::egress::rules::{self as ops, Rules};
use crate::server::Hub;
use crate::store::{
    Coverages, MAX_OBSERVED_CONTACTS, ObservedFilter, ObservedSubject, ObservedUse, UNREPORTED,
};

/// The query's value of `tab` that asks for this tab.
const TAB: &str = "observed";

/// The ID of the part of the page its filter's form replaces.
const RESULTS: &str = "observed-results";

/// The days a destination's recent use is counted over.
const RECENT_DAYS: u64 = 30;

/// The refs a destination lists, the most jobs first.
const SHOWN_REFS: usize = 3;

/// What the tab shows: every project, or one project's destinations, matching every set field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Query {
    subject: Option<Subject>,
    /// A [`crate::egress::blocked::phase_key`].
    phase: Option<&'static str>,
    /// A [`crate::egress::observed::protection_key`].
    protection: Option<&'static str>,
}

impl Query {
    /// `/egress?tab=observed[&project=…&phase=…&protection=…]`; `None` for another tab. A value
    /// that cannot be one is ignored.
    pub(super) fn of(query: Option<&str>) -> Option<Query> {
        let query = decode_form(query.unwrap_or("").as_bytes());
        if field(&query, "tab") != Some(TAB) {
            return None;
        }
        let pick = |name: &str, from: &[&'static str]| {
            field(&query, name).and_then(|v| from.iter().copied().find(|k| *k == v))
        };
        let phases: Vec<&'static str> = PHASES.iter().map(|(k, _)| *k).collect();
        let protections: Vec<&'static str> = PROTECTIONS.iter().map(|(k, _)| *k).collect();
        Some(Query {
            subject: field(&query, "project").and_then(Subject::parse),
            phase: pick("phase", &phases),
            protection: pick("protection", &protections),
        })
    }

    /// `/egress?tab=observed…` with this query, as an attribute's value.
    fn href(&self) -> String {
        let subject = self.subject.as_ref().map(Subject::param);
        let mut out = format!("{PATH}?tab={TAB}");
        for (name, value) in [
            ("project", subject.as_deref()),
            ("phase", self.phase),
            ("protection", self.protection),
        ] {
            if let Some(value) = value {
                out.push('&');
                out.push_str(name);
                out.push('=');
                out.push_str(&percent_encode(value));
            }
        }
        out
    }

    fn filter(&self) -> ObservedFilter<'static> {
        ObservedFilter {
            phase: self.phase,
            protection: self.protection,
        }
    }
}

/// `/egress?tab=observed&project=<subject>`: `subject`'s Observed traffic, as an attribute's
/// value.
pub(super) fn subject_href(subject: &Subject) -> String {
    Query {
        subject: Some(subject.clone()),
        ..Query::default()
    }
    .href()
}

/// One project's destinations, as shown.
struct Project {
    coverage: Coverages,
    uses: Vec<ObservedUse>,
    /// The Blocked tab's rows of the same destinations, by [`Finding::text`]: each one's view,
    /// ID and jobs.
    refused: HashMap<String, Vec<(View, String, u64)>>,
}

/// What the tab shows.
struct Listing {
    subjects: Vec<(String, ObservedSubject)>,
    /// Each project's coverage, for the list of projects.
    coverages: HashMap<String, Coverages>,
    /// The query's project, when it names one.
    project: Option<Project>,
    unreported: Vec<(String, String)>,
    rules: Rules,
    /// The nodes, and the rules' entries' use and their caps', for the list of projects.
    nodes: Vec<(String, crate::store::NodeRow)>,
    used: Option<Arc<Aggregates>>,
    /// The instance its projects leave unnamed ([`crate::store::Db::sole_gitlab`]).
    sole: Option<String>,
}

fn listing(hub: &Hub, caches: &Caches, q: &Query) -> Result<Listing> {
    let subjects = hub.db.observed_subjects()?;
    let mut coverages = HashMap::new();
    let project = match &q.subject {
        Some(subject) => {
            let mut uses = hub.db.observed_uses(subject, q.filter())?;
            uses.sort_by(|a, b| {
                b.last_ms
                    .cmp(&a.last_ms)
                    .then_with(|| a.contact.text().cmp(&b.contact.text()))
                    .then_with(|| a.phase.cmp(&b.phase))
            });
            // The Blocked rows of the destinations shown, each once.
            let mut wanted: HashMap<String, (View, String)> = HashMap::new();
            for u in uses.iter().take(PAGE_ROWS) {
                for view in [View::Blocked, View::WouldBlock] {
                    let finding = Finding::Denial {
                        view,
                        protocol: u.contact.protocol,
                        destination: u.contact.destination.clone(),
                    };
                    wanted.insert(row_id(subject, &finding), (view, finding.text()));
                }
            }
            let ids: Vec<&String> = wanted.keys().collect();
            let mut refused: HashMap<String, Vec<(View, String, u64)>> = HashMap::new();
            for (id, row) in hub.db.egress_rows_of(&ids)? {
                if let Some((view, text)) = wanted.get(&id) {
                    refused
                        .entry(text.clone())
                        .or_default()
                        .push((*view, id, row.jobs));
                }
            }
            for rows in refused.values_mut() {
                rows.sort_by_key(|(view, _, _)| *view != View::Blocked);
            }
            Some(Project {
                coverage: hub.db.observed_coverage(subject, q.filter())?,
                uses,
                refused,
            })
        }
        None => {
            for (param, _) in &subjects {
                if let Some(subject) = Subject::parse(param) {
                    coverages.insert(
                        param.clone(),
                        hub.db.observed_coverage(&subject, q.filter())?,
                    );
                }
            }
            None
        }
    };
    let rules = ops::list(hub)?;
    let nodes = match project {
        None => hub.db.nodes()?,
        Some(_) => Vec::new(),
    };
    let used = match project {
        None => Some(
            caches
                .aggregates
                .get(hub, &rules, &nodes, crate::now_secs())?,
        ),
        Some(_) => None,
    };
    Ok(Listing {
        subjects,
        coverages,
        project,
        unreported: unreported(hub)?,
        rules,
        nodes,
        used,
        sole: hub.db.sole_gitlab()?,
    })
}

/// What `/events/egress?tab=observed…` streams: the listing of the query, as the jobs' reports
/// change.
pub(super) fn source(hub: &Arc<Hub>, caches: &Arc<Caches>, q: Query, steer: bool) -> Source {
    let changes = hub.subscribe_egress();
    let (hub, caches) = (hub.clone(), caches.clone());
    Source::Own {
        name: EVENT,
        changes,
        render: Arc::new(move || {
            let mut h = Html::new();
            results(
                &mut h,
                &q,
                &listing(&hub, &caches, &q)?,
                crate::now_secs(),
                steer,
            );
            Ok(h.into_string())
        }),
    }
}

/// `GET /egress?tab=observed…` ([`Query::of`]).
pub(super) async fn get(
    q: Query,
    auth: &Auth,
    caches: &Arc<Caches>,
    ui: &Ui,
) -> Result<Response<Body>> {
    let (hub, caches, wanted) = (ui.hub.clone(), caches.clone(), q.clone());
    let listing = blocking(move || listing(&hub, &caches, &wanted)).await?;
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, super::Tab::Observed, q.subject.as_ref());
    unreported_callout(&mut h, &listing.unreported);
    h.raw("<p class=\"sub\">What the jobs of the history reached, by destination and project, ")
        .raw("as their nodes reported it: allowed, or carried while a dry-run allowlist would ")
        .raw("have blocked it. A DNS entry is a lookup, not proof of a connection.</p>");
    filter_form(&mut h, &q, &listing.subjects, listing.sole.as_deref());
    h.raw("<div id=\"")
        .raw(RESULTS)
        .raw("\"><div hx-ext=\"sse\" sse-connect=\"/events/")
        .raw(EVENT)
        .text(q.href().strip_prefix(PATH).unwrap_or_default())
        .raw("\" sse-swap=\"")
        .raw(EVENT)
        .raw("\" sse-close=\"close\">");
    let steer = auth.session.role >= crate::store::Role::Operator;
    results(&mut h, &q, &listing, crate::now_secs(), steer);
    h.raw("</div></div>");
    Ok(page(fleet::layout("Egress", PATH, auth, &h)))
}

/// The filter's form: project, phase and protection, applied at once with htmx as on the
/// Blocked tab.
fn filter_form(
    h: &mut Html,
    q: &Query,
    subjects: &[(String, ObservedSubject)],
    sole: Option<&str>,
) {
    h.raw("<form id=\"observed-filter\" class=\"filter\" method=\"get\" action=\"")
        .raw(PATH)
        .raw("\" hx-get=\"")
        .raw(PATH)
        .raw("\" hx-trigger=\"submit, change from:(#observed-filter select)\" hx-target=\"#")
        .raw(RESULTS)
        .raw("\" hx-select=\"#")
        .raw(RESULTS)
        .raw("\" hx-swap=\"outerHTML\" hx-push-url=\"true\" hx-sync=\"this:replace\">")
        .raw("<input type=\"hidden\" name=\"tab\" value=\"")
        .raw(TAB)
        .raw("\">");
    let mut named: Vec<(&String, String)> =
        subjects.iter().map(|(p, s)| (p, who(p, s, sole))).collect();
    named.sort_by(|a, b| (&a.1, a.0).cmp(&(&b.1, b.0)));
    let chosen = q.subject.as_ref().map(Subject::param);
    h.raw("<select name=\"project\" aria-label=\"Project\">")
        .raw("<option value=\"\">Every project</option>");
    if let Some(c) = chosen
        .as_ref()
        .filter(|c| !named.iter().any(|(p, _)| *p == *c))
    {
        h.raw("<option value=\"")
            .text(c)
            .raw("\" selected>")
            .text(c)
            .raw("</option>");
    }
    for (param, name) in &named {
        h.raw("<option value=\"").text(param).raw("\"");
        if chosen.as_ref() == Some(*param) {
            h.raw(" selected");
        }
        h.raw(">").node(name).raw("</option>");
    }
    h.raw("</select><select name=\"phase\" aria-label=\"Phase\">")
        .raw("<option value=\"\">Every phase</option>");
    for (phase, label) in PHASES {
        h.raw("<option value=\"").raw(phase).raw("\"");
        if q.phase == Some(phase) {
            h.raw(" selected");
        }
        h.raw(">").raw(label).raw("</option>");
    }
    h.raw("</select><select name=\"protection\" aria-label=\"Protection\">")
        .raw("<option value=\"\">Every ref</option>");
    for (protection, label) in PROTECTIONS {
        h.raw("<option value=\"").raw(protection).raw("\"");
        if q.protection == Some(protection) {
            h.raw(" selected");
        }
        h.raw(">").raw(label).raw("</option>");
    }
    h.raw("</select> <button>Show</button></form>");
}

/// A project as pages name it ([`Subject::label`]), or its subject's param when it cannot be
/// read.
fn who(param: &str, s: &ObservedSubject, sole: Option<&str>) -> String {
    match Subject::parse(param) {
        Some(subject) => subject.label(s.project.as_deref(), &s.key_name, sole),
        None => param.to_string(),
    }
}

/// The part of the page that follows the jobs' reports: every project, or one project's
/// destinations, with proposals from them when `steer`. No form: a choice being made is never
/// reset by an update.
fn results(h: &mut Html, q: &Query, l: &Listing, now: u64, steer: bool) {
    match (&q.subject, &l.project) {
        (Some(subject), Some(p)) => project(h, q, subject, l, p, now, steer),
        _ => projects(h, q, l),
    }
}

/// `1 job`, `2 jobs`.
fn jobs_text(n: u64) -> String {
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} job{plural}")
}

/// How completely the jobs reported each phase: `Run: 84 of 100 jobs reported this phase
/// completely`, then those that sent no report.
fn coverage_lines(c: &Coverages) -> Vec<String> {
    let mut out = Vec::new();
    for (key, label) in PHASES {
        if let Some(p) = c.phases.get(key) {
            out.push(format!(
                "{label}: {} of {} reported this phase completely",
                p.complete,
                jobs_text(p.ran)
            ));
        }
    }
    if let Some(p) = c.phases.get(UNREPORTED) {
        out.push(format!("{} sent no report", jobs_text(p.ran)));
    }
    out
}

/// Every project, its latest first, with how completely its jobs reported; then the rules'
/// entries no contact matched.
fn projects(h: &mut Html, q: &Query, l: &Listing) {
    if let Some(u) = &l.used {
        if !l.rules.rules.is_empty() {
            unused_callout(h, &u.rule_use);
        }
        let nodes: Vec<&(String, crate::store::NodeRow)> = l.nodes.iter().collect();
        super::rules::caps_unused(h, &nodes, &u.cap_use);
    }
    if l.subjects.is_empty() {
        h.raw("<p class=\"empty\">nothing observed yet</p>");
        return;
    }
    let mut subjects: Vec<&(String, ObservedSubject)> = l.subjects.iter().collect();
    subjects.sort_by(|a, b| b.1.latest_at.cmp(&a.1.latest_at).then(a.0.cmp(&b.0)));
    h.raw("<table class=\"grid\"><thead><tr><th>project</th><th class=\"num\">jobs reported</th>")
        .raw("<th class=\"num\">destinations</th><th>coverage</th><th>latest</th>")
        .raw("</tr></thead><tbody>");
    for (param, s) in subjects.iter().take(PAGE_ROWS) {
        let chosen = Query {
            subject: Subject::parse(param),
            ..q.clone()
        };
        h.raw("<tr><td><a href=\"")
            .text(chosen.href())
            .raw("\">")
            .node(&who(param, s, l.sole.as_deref()))
            .raw("</a></td><td class=\"num\">")
            .text(s.jobs)
            .raw("</td><td class=\"num\">")
            .text(s.contacts);
        if s.dropped > 0 {
            h.raw(" <span class=\"badge warn\" title=\"")
                .text(dropped_text(s.dropped))
                .raw("\">bound reached</span>");
        }
        h.raw("</td><td>");
        let lines = l
            .coverages
            .get(param.as_str())
            .map(coverage_lines)
            .unwrap_or_default();
        h.text(lines.join(" · ")).raw("</td><td>");
        super::super::pages::at(h, s.latest_at);
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table><p class=\"sub\">Jobs and destinations count every phase and ref, ")
        .raw("destinations phase by phase; coverage follows the filter.</p>");
}

/// Why some contacts are not listed.
fn dropped_text(n: u64) -> String {
    format!(
        "{n} contacts of its jobs are not listed: the project reached the {MAX_OBSERVED_CONTACTS} \
         destinations kept of it."
    )
}

/// `day` (since the epoch) as a date: `2026-10-23`.
pub(super) fn date(day: u64) -> String {
    let mut s = crate::utc(day.saturating_mul(86_400));
    s.truncate(10);
    s
}

/// One project's destinations, the latest used first.
fn project(
    h: &mut Html,
    q: &Query,
    subject: &Subject,
    l: &Listing,
    p: &Project,
    now: u64,
    steer: bool,
) {
    let summary = l
        .subjects
        .iter()
        .find(|(param, _)| *param == subject.param())
        .map(|(param, s)| (who(param, s, l.sole.as_deref()), s));
    h.raw("<h2>");
    match &summary {
        Some((name, _)) => h.node(name),
        None => h.text(subject.param()),
    };
    h.raw("</h2><p><a href=\"")
        .text(super::subject_href(subject))
        .raw("\">Its rows on the Blocked tab</a> · <a href=\"")
        .text(
            Query {
                subject: None,
                ..q.clone()
            }
            .href(),
        )
        .raw("\">Every project</a></p>");
    let lines = coverage_lines(&p.coverage);
    if !lines.is_empty() {
        h.raw("<ul class=\"access\">");
        for line in &lines {
            h.raw("<li>").text(line).raw("</li>");
        }
        h.raw("</ul>");
    }
    if let Some(day) = p.coverage.since_day {
        h.raw("<p class=\"sub\">From its jobs since ")
            .text(date(day))
            .raw(", as long as the job history keeps them. No contact in it does not prove a ")
            .raw("destination unnecessary.</p>");
    }
    if let Some((_, s)) = summary.as_ref().filter(|(_, s)| s.dropped > 0) {
        h.raw("<p class=\"callout warn\">")
            .text(dropped_text(s.dropped))
            .raw("</p>");
    }
    if p.uses.is_empty() {
        h.raw(if summary.is_none() {
            "<p class=\"empty\">nothing observed yet</p>"
        } else {
            "<p class=\"empty\" role=\"status\">none match</p>"
        });
        return;
    }
    let uses = &p.uses;
    let project_path = summary.as_ref().and_then(|(_, s)| s.project.as_deref());
    let today = now / 86_400;
    let since = today.saturating_sub(RECENT_DAYS - 1);
    h.raw("<table class=\"grid\"><thead><tr><th>destination</th><th>phase</th>")
        .raw("<th class=\"num\">jobs</th><th class=\"num\">attempts</th><th>first seen</th>")
        .raw("<th>last seen</th><th class=\"num\" title=\"The days a job first used it on, in the last 30\">days, last 30</th><th>refs</th>")
        .raw("<th>latest job</th><th>also refused</th><th>under current rules</th></tr>")
        .raw("</thead><tbody>");
    for u in uses.iter().take(PAGE_ROWS) {
        let text = u.contact.text();
        h.raw("<tr><td><code>").node(&text).raw("</code>");
        if u.contact.protocol == vk_hub_proto::egress::EgressProtocol::Dns {
            h.raw(" <span class=\"sub\">lookup</span>");
        }
        if u.contact.outcome == vk_hub_proto::egress::EgressOutcome::WouldBlock {
            h.raw(" <span class=\"badge warn\" title=\"A dry-run allowlist would have blocked ")
                .raw("it; the switch carried it.\">would block</span>");
        }
        let phase = PHASES
            .iter()
            .find(|(k, _)| *k == u.phase)
            .map_or("Other", |(_, label)| *label);
        h.raw("</td><td>")
            .raw(phase)
            .raw("</td><td class=\"num\">")
            .text(u.jobs)
            .raw("</td><td class=\"num\">")
            .text(u.attempts)
            .raw("</td><td>")
            .text(date(u.first_day))
            .raw("</td><td title=\"On its node's clock\">")
            .text(super::super::pages::started(u.last_ms / 1000))
            .raw("</td><td class=\"num\">")
            .text(u.days.range(since..).count())
            .raw("</td><td>");
        refs(h, u);
        h.raw("</td><td>");
        if u.last_job.is_empty() {
            h.raw("-");
        } else {
            h.raw("<a href=\"")
                .raw(super::super::jobs::DETAIL_PREFIX)
                .text(&u.last_job)
                .raw("\">")
                .text(u.last_job.get(..8).unwrap_or(&u.last_job))
                .raw("</a>");
        }
        h.raw("</td><td>");
        match p.refused.get(&text) {
            Some(rows) => {
                for (i, (view, id, jobs)) in rows.iter().enumerate() {
                    if i > 0 {
                        h.raw(", ");
                    }
                    h.raw("<a href=\"")
                        .raw(ROW_PREFIX)
                        .text(id)
                        .raw("\">")
                        .raw(view.label())
                        .raw("</a> (")
                        .text(jobs_text(*jobs))
                        .raw(")");
                }
            }
            None => {
                h.raw("-");
            }
        }
        h.raw("</td><td>");
        let outside = compared(h, &l.rules, subject, project_path, u);
        if steer && outside && Dest::of(&u.contact.destination).is_some() {
            let who = summary
                .as_ref()
                .map_or_else(|| subject.param(), |(name, _)| name.clone());
            h.raw("<div class=\"sub\">");
            super::proposal_link(
                h,
                &super::propose::contact_href(subject, &u.phase, &u.contact),
                &who,
                None,
            );
            h.raw("</div>");
        }
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table>");
    if let Some(more) = uses.len().checked_sub(PAGE_ROWS).filter(|n| *n > 0) {
        h.raw("<p class=\"sub\">")
            .text(more)
            .raw(" more, used longer ago: narrow the filter to see them.</p>");
    }
    h.raw("<p class=\"sub\">Times are its nodes' clocks. Also refused: the project's rows of ")
        .raw("the same destination on the Blocked tab, in any phase. Under current rules: as ")
        .raw("the rules saved now would treat each of its refs, not as its jobs ran.</p>");
}

/// A destination's refs, the most jobs first: `main (protected) ×12, topic ×3, 2 more`.
fn refs(h: &mut Html, u: &ObservedUse) {
    let mut refs: Vec<(&(String, String), &u64)> = u.refs.iter().collect();
    refs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (i, ((git_ref, protection), jobs)) in refs.iter().take(SHOWN_REFS).enumerate() {
        if i > 0 {
            h.raw(", ");
        }
        match git_ref.as_str() {
            "" => h.raw("no ref"),
            r => h.node(r),
        };
        match protection.as_str() {
            "protected" => h.raw(" (protected)"),
            "unprotected" => h.raw(""),
            _ => h.raw(" (protection not reported)"),
        };
        h.raw(" ×").text(jobs);
    }
    if let Some(more) = refs.len().checked_sub(SHOWN_REFS).filter(|n| *n > 0) {
        h.raw(", ").text(more).raw(" more");
    }
}

/// How the rules saved now treat `u`'s destination for each of its refs: `Allowed by wab ·
/// debian.org`, `Outside current hub rules for 1 of 3 refs`. Returns whether they leave it
/// outside, or allow it by name only, for any of them.
fn compared(
    h: &mut Html,
    rules: &Rules,
    subject: &Subject,
    project: Option<&str>,
    u: &ObservedUse,
) -> bool {
    if rules.rules.is_empty() {
        h.raw(if rules.enabled {
            "<span class=\"badge warn\">Outside current hub rules</span> <span class=\"sub\">no \
             rules saved</span>"
        } else {
            "<span class=\"sub\">No saved rules: once on, the hub would allow nothing</span>"
        });
        return true;
    }
    let Some(dest) = Dest::of(&u.contact.destination) else {
        h.raw("-");
        return false;
    };
    let mut allowed: Vec<String> = Vec::new();
    let (mut outside, mut by_name) = (0usize, 0usize);
    for (git_ref, protection) in u.refs.keys() {
        match rule_use::compare(
            &rules.rules,
            subject,
            project,
            protection,
            git_ref,
            &u.phase,
            &dest,
        ) {
            Compared::Allowed(by) => {
                for b in by {
                    if !allowed.contains(&b) {
                        allowed.push(b);
                    }
                }
            }
            Compared::ByNameOnly => by_name += 1,
            Compared::Outside => outside += 1,
        }
    }
    if !rules.enabled {
        h.raw("<span class=\"sub\">If on:</span> ");
    }
    let refs = u.refs.len();
    if outside > 0 {
        h.raw("<span class=\"badge warn\">Outside current hub rules</span>");
        if outside < refs {
            h.raw(" for ")
                .text(outside)
                .raw(" of ")
                .text(refs)
                .raw(" refs");
        }
    }
    if by_name > 0 {
        if outside > 0 {
            h.raw("; ");
        }
        h.raw("Not allowed by address: only if a listed name's lookup resolved to it");
    }
    if !allowed.is_empty() {
        if outside + by_name > 0 {
            h.raw("; otherwise ");
        }
        h.raw("Allowed by ").text(allowed.join("; "));
    }
    outside + by_name > 0
}

/// The most entries with no observed use the list of projects names.
const SHOWN_UNUSED: usize = 50;

/// The rules' entries no contact matched within 30 days, each with its last use and its
/// coverage, and the caution that goes with them.
pub(super) fn unused_callout(h: &mut Html, u: &RuleUse) {
    let unused: Vec<(&String, &'static str, &String)> = u
        .entries
        .keys()
        .filter(|(r, p, e)| u.standing(r, p, e) == rule_use::Standing::Unused)
        .map(|(r, p, e)| (r, *p, e))
        .collect();
    if unused.is_empty() {
        return;
    }
    h.raw("<div class=\"callout\"><p><span class=\"badge\">No observed use in 30 days</span> ")
        .raw("No contact of the jobs these rules apply to matched these entries:</p>")
        .raw("<ul class=\"access\">");
    for (rule, phase, entry) in unused.iter().take(SHOWN_UNUSED) {
        h.raw("<li><a href=\"")
            .text(super::rules::rule_href(rule))
            .raw("\"><strong>")
            .text(if *rule == crate::store::DEFAULT_RULE {
                "Fallback"
            } else {
                rule.as_str()
            })
            .raw("</strong></a> · ")
            .raw(if *phase == "build" { "Build" } else { "Run" })
            .raw(" · <code>")
            .text(entry)
            .raw("</code> · ")
            .text(use_text(u, rule, phase, entry))
            .raw("</li>");
    }
    h.raw("</ul>");
    if unused.len() > SHOWN_UNUSED {
        h.raw("<p class=\"sub\">")
            .text(unused.len() - SHOWN_UNUSED)
            .raw(" more, on their rules' pages.</p>");
    }
    caution(h, u);
    h.raw("</div>");
}

/// An entry's last use and its rule's coverage of the phase: `last used 2026-09-04 · 84 of 100
/// applicable jobs reported this phase completely`.
pub(super) fn use_text(u: &RuleUse, rule: &str, phase: &'static str, entry: &str) -> String {
    let last = u
        .entries
        .get(&(rule.to_string(), phase, entry.to_string()))
        .and_then(|e| e.last_day);
    let last = match last {
        Some(day) => format!("last used {}", date(day)),
        None => "not seen in the history kept".to_string(),
    };
    let c = u
        .coverage
        .get(&(rule.to_string(), phase))
        .copied()
        .unwrap_or_default();
    format!(
        "{last} · {} of {} applicable jobs reported this phase completely",
        c.complete, c.ran
    )
}

/// What qualifies a rule entry's use: how far back the history goes, what was not kept or read,
/// and that no reported use does not prove an entry unnecessary.
pub(super) fn caution(h: &mut Html, u: &RuleUse) {
    h.raw("<p class=\"sub\">");
    if let Some(day) = u.since_day {
        h.raw("The history's reports go back to ")
            .text(date(day))
            .raw(". ");
    }
    let dropped: u64 = u.dropped.values().sum();
    if dropped > 0 {
        h.text(dropped)
            .raw(" contacts of these projects were not kept, past their bound. ");
    }
    if u.capped {
        h.raw("Observed traffic was read only in part. ");
    }
    h.raw("Only placed jobs report, never gitlab-runner's. No reported use does not prove an ")
        .raw("entry unnecessary; nothing is removed automatically.</p>");
}
