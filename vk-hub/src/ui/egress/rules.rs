//! `/egress?tab=rules`: the Egress page's *Rules* tab, for viewers and operators alike — the
//! hub's egress rules ([`crate::egress::rules`]), each with the jobs it selects in plain words,
//! what each phase may reach under it, its mode, and the recent jobs placed under it; the
//! Fallback listed apart. With `[jobs] egress_rules` off the tab says that saved rules restrict
//! nothing. Each rule has a page of its own, `/egress?tab=rules&rule=<name>`, listing its
//! entries and each one's use; there operators change or remove it, and on
//! `/egress?tab=rules&new=rule` add one, through Preview → Save ([`super::editor`]). Below the
//! rules, each node's own caps as it reports them, with the entries of them the hub's jobs
//! placed under them show no use of ([`crate::egress::cap_use`]). The list, and a rule's page
//! but its forms, follow the rules, the jobs' reports and the nodes' caps over
//! `/events/egress?tab=rules[&rule=…]`.
//!
//! Rule names and entries are operators' to choose, checked as a node checks its own lists;
//! they are escaped as any text.

use std::sync::Arc;

use anyhow::Result;
use hyper::{Response, StatusCode};
use vk_hub_proto::egress::{HubPhase, NodeEgressCaps};

use super::super::html::Html;
use super::super::jobs::percent_encode;
use super::super::pages;
use super::super::sse::Source;
use super::super::{Auth, Body, Ui, access, blocking, decode_form, field, fleet, message, page};
use super::{Caches, PATH as EGRESS, Tab, capital};
use crate::egress::aggregates::Aggregates;
use crate::egress::cap_use::CapUse;
use crate::egress::rule_use::{self, RuleUse, Standing};
use crate::egress::rules::{self as ops, RECENT_SCAN, RuleJobs, Rules};
use crate::server::Hub;
use crate::store::{DEFAULT_RULE, EgressRuleRow, NodeRow, Role, RuleMode};

/// The tab.
pub(super) const PATH: &str = "/egress?tab=rules";

/// The query's value of `tab` that asks for this tab.
const TAB: &str = "rules";

/// What the tab shows: every rule, or one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Query {
    /// A rule's name: its page.
    rule: Option<String>,
    /// The form for a rule to add: the Fallback when `Some(true)`.
    new: Option<bool>,
}

impl Query {
    /// `/egress?tab=rules[&rule=…]`; `None` for another tab. A name that cannot be a rule's is
    /// ignored.
    pub(super) fn of(query: Option<&str>) -> Option<Query> {
        let query = decode_form(query.unwrap_or("").as_bytes());
        if field(&query, "tab") != Some(TAB) {
            return None;
        }
        Some(Query {
            rule: field(&query, "rule")
                .filter(|r| vk_hub_proto::egress::valid_rule_name(r))
                .map(str::to_string),
            new: match field(&query, "new") {
                Some("rule") => Some(false),
                Some("fallback") => Some(true),
                _ => None,
            },
        })
    }
}

/// Rule `name`'s page, as an attribute's value.
pub(super) fn rule_href(name: &str) -> String {
    format!("{PATH}&rule={}", percent_encode(name))
}

/// What the tab shows.
struct Listing {
    rules: Rules,
    /// The GitLab instances, by name, for the editor.
    gitlabs: Vec<String>,
    /// The enrolled nodes, by ID.
    nodes: Vec<(String, NodeRow)>,
    /// The rules' entries' use, the caps', and the recent jobs.
    used: Arc<Aggregates>,
}

fn listing(hub: &Hub, caches: &Caches) -> Result<Listing> {
    let rules = ops::list(hub)?;
    let mut nodes = hub.db.nodes()?;
    nodes.sort_by(|a, b| (&a.1.hostname, &a.0).cmp(&(&b.1.hostname, &b.0)));
    Ok(Listing {
        used: caches
            .aggregates
            .get(hub, &rules, &nodes, crate::now_secs())?,
        nodes,
        rules,
        gitlabs: hub.db.gitlabs()?.into_iter().map(|(n, _)| n).collect(),
    })
}

/// What `/events/egress?tab=rules[&rule=…]` streams: the tab's list, or a rule's page but its
/// forms, as the rules, the jobs' reports and the nodes' caps change.
pub(super) fn source(hub: &Arc<Hub>, caches: &Arc<Caches>, q: Query) -> Source {
    let changes = hub.subscribe_egress();
    let (hub, caches) = (hub.clone(), caches.clone());
    Source::Own {
        name: super::EVENT,
        changes,
        render: Arc::new(move || {
            let l = listing(&hub, &caches)?;
            let mut h = Html::new();
            match &q.rule {
                Some(name) => match l.rules.rules.iter().find(|r| r.name == *name) {
                    Some(r) => rule_results(&mut h, &l, r),
                    None => {
                        h.raw("<p class=\"empty\" role=\"status\">There is no such rule: it ")
                            .raw("may have been removed.</p>");
                    }
                },
                None => tab_results(&mut h, &l),
            }
            Ok(h.into_string())
        }),
    }
}

/// The part of a page that follows `/events/egress?tab=rules[&rule=<rule>]`, its content left
/// to the caller to close with [`live_end`].
fn live_start(h: &mut Html, rule: Option<&str>) {
    h.raw("<div hx-ext=\"sse\" sse-connect=\"/events/")
        .raw(super::EVENT)
        .raw("?tab=")
        .raw(TAB);
    if let Some(r) = rule {
        h.raw("&amp;rule=").text(percent_encode(r));
    }
    h.raw("\" sse-swap=\"")
        .raw(super::EVENT)
        .raw("\" sse-close=\"close\">");
}

fn live_end(h: &mut Html) {
    h.raw("</div>");
}

/// `GET /egress?tab=rules…` ([`Query::of`]).
pub(super) async fn get(
    q: Query,
    auth: &Auth,
    caches: &Arc<Caches>,
    ui: &Ui,
) -> Result<Response<Body>> {
    let (hub, caches) = (ui.hub.clone(), caches.clone());
    let listing = blocking(move || listing(&hub, &caches)).await?;
    let operator = auth.session.role >= Role::Operator;
    let main = match (&q.rule, q.new) {
        (None, Some(fallback)) if operator => {
            super::editor::new_page(&listing.rules, fallback, &listing.gitlabs, auth)
        }
        (Some(name), _) => {
            let Some(rule) = listing.rules.rules.iter().find(|r| r.name == *name) else {
                return Ok(message(
                    StatusCode::NOT_FOUND,
                    "There is no such rule: it may have been removed.",
                ));
            };
            rule_page(&listing, rule, auth)
        }
        _ => tab_page(&listing, auth),
    };
    Ok(page(fleet::layout("Egress", EGRESS, auth, &main)))
}

/// Whether `r` is the Fallback.
fn is_fallback(r: &EgressRuleRow) -> bool {
    r.name == DEFAULT_RULE
}

/// A rule's name as a page says it: the Fallback as such.
pub(super) fn rule_name(r: &EgressRuleRow) -> &str {
    if is_fallback(r) { "Fallback" } else { &r.name }
}

/// The jobs rule `r` selects, in plain words.
pub(super) fn applies_to(r: &EgressRuleRow) -> String {
    match &r.subject {
        Some(s) => access::who(s),
        None => "Jobs no enforced rule selects, and every gitlab-runner job".to_string(),
    }
}

/// The callout that says how the rules stand: off, with rules saved; on, with a warning.
pub(super) fn state_callout(h: &mut Html, rules: &Rules) {
    if !rules.enabled {
        h.raw("<div class=\"callout\"><p><strong>Hub rules are off.</strong> Saved rules ")
            .raw("restrict nothing yet: they apply once <code>hub.toml</code> sets ")
            .raw("<code>[jobs] egress_rules = true</code>. Node caps and jobs' own ")
            .raw("restrictions still apply.</p></div>");
        return;
    }
    if let Some(warning) = rules.warning() {
        h.raw("<p class=\"callout warn\">")
            .text(capital(warning))
            .raw(".</p>");
    }
}

fn tab_page(l: &Listing, auth: &Auth) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, Tab::Rules, None);
    h.raw("<p class=\"sub\">What jobs may reach, by project, ref and protection, in each phase. ")
        .raw("Matching enforced rules add up: a rule cannot remove access another allows. Node ")
        .raw("caps and jobs' own restrictions still apply.</p>");
    if auth.session.role >= Role::Operator {
        h.raw("<p class=\"actions\"><a href=\"")
            .raw(PATH)
            .raw("&amp;new=rule\">Add a rule</a>");
        if !l.rules.rules.iter().any(is_fallback) {
            h.raw(" <a href=\"")
                .raw(PATH)
                .raw("&amp;new=fallback\">Add the Fallback</a>");
        }
        h.raw("</p>");
    }
    live_start(&mut h, None);
    tab_results(&mut h, l);
    live_end(&mut h);
    h
}

/// The tab's list: how the rules stand, the rules, the Fallback and the nodes' caps. No form:
/// what is being typed elsewhere on the page is never reset by an update.
fn tab_results(h: &mut Html, l: &Listing) {
    state_callout(h, &l.rules);
    let (fallback, rules): (Vec<&EgressRuleRow>, Vec<&EgressRuleRow>) =
        l.rules.rules.iter().partition(|r| is_fallback(r));
    if rules.is_empty() && fallback.is_empty() {
        h.raw("<p class=\"empty\">no rules yet</p>");
        node_caps(h, &l.nodes, &l.used.cap_use);
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>rule</th><th>applies to</th><th>run</th>")
        .raw("<th>build</th><th>mode</th><th>last 7 days</th></tr></thead><tbody>");
    for r in &rules {
        rule_row(h, r, l);
    }
    h.raw("</tbody></table>");
    h.raw("<h2>Fallback</h2>");
    match fallback.first() {
        Some(f) => {
            h.raw("<table class=\"grid\"><thead><tr><th>rule</th><th>applies to</th><th>run</th>")
                .raw("<th>build</th><th>mode</th><th>last 7 days</th></tr></thead><tbody>");
            rule_row(h, f, l);
            h.raw("</tbody></table>");
        }
        None => {
            h.raw("<p class=\"empty\">no Fallback: once rules are on, a job no enforced rule ")
                .raw("selects, and every gitlab-runner job, may reach nothing</p>");
        }
    }
    if l.used.recent.capped {
        h.raw("<p class=\"sub\">Recent jobs: the latest ")
            .text(RECENT_SCAN)
            .raw(" of the last 7 days.</p>");
    }
    node_caps(h, &l.nodes, &l.used.cap_use);
}

/// A node's cap's phase in a few words: `Unrestricted`, `No external access`,
/// `corp.example.com + 1 IP range`.
pub(super) fn cap_summary(p: &HubPhase) -> String {
    match p {
        HubPhase::Unrestricted => "Unrestricted".to_string(),
        p => phase_summary(p),
    }
}

/// Each node's own caps as it reports them, with the entries of them the hub's jobs show no use
/// of.
fn node_caps(h: &mut Html, nodes: &[(String, NodeRow)], u: &CapUse) {
    let nodes: Vec<&(String, NodeRow)> = nodes
        .iter()
        .filter(|(_, n)| n.inventory.is_some())
        .collect();
    if nodes.is_empty() {
        return;
    }
    h.raw("<section id=\"caps\"><h2>Node caps</h2><p class=\"sub\">Each node's own ")
        .raw("<code>[egress]</code> and <code>[egress.build]</code>, as it reports them: what ")
        .raw("its jobs may ever reach, whatever the hub's rules allow. A hub rule cannot widen ")
        .raw("them.</p><table class=\"grid\"><thead><tr><th>node</th><th>run</th><th>build</th>")
        .raw("<th>last 30 days</th></tr></thead><tbody>");
    for (id, n) in &nodes {
        h.raw("<tr><td><a href=\"/node/")
            .text(id)
            .raw("\">")
            .node(&n.hostname)
            .raw("</a></td>");
        let reported = n.inventory.as_ref().and_then(|i| i.egress_caps.as_ref());
        let c = match reported {
            Some(NodeEgressCaps::Listed(c)) => c,
            Some(NodeEgressCaps::TooLarge) => {
                h.raw("<td colspan=\"3\">too large to report</td></tr>");
                continue;
            }
            Some(NodeEgressCaps::Other) => {
                h.raw("<td colspan=\"3\">reported in a form this hub cannot read</td></tr>");
                continue;
            }
            None => {
                h.raw("<td colspan=\"3\">not reported: a newer <code>vk</code> reports them</td></tr>");
                continue;
            }
        };
        h.raw("<td>").text(cap_summary(&c.run));
        if c.run_dry_run {
            h.raw(" <span class=\"badge warn\">Dry-run</span>");
        }
        h.raw("</td><td>")
            .text(cap_summary(&c.build))
            .raw("</td><td>");
        match u.unused(id).len() {
            0 => h.raw("-"),
            1 => h.raw("1 entry with no observed use"),
            n => h.text(n).raw(" entries with no observed use"),
        };
        if let Some(n) = u.unreported.get(id.as_str()).filter(|n| **n > 0) {
            h.raw("; ").text(jobs_text(*n)).raw(" sent no report");
        }
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table>");
    caps_unused(h, &nodes, u);
    h.raw("</section>");
}

/// The entries of the nodes' caps no contact of the hub's jobs placed under them matched within
/// 30 days, each with its last use and its coverage, and the caution that goes with them.
pub(super) fn caps_unused(h: &mut Html, nodes: &[&(String, NodeRow)], u: &CapUse) {
    let today = crate::now_secs() / 86_400;
    let window = today.saturating_sub(rule_use::USE_DAYS - 1);
    let mut any = false;
    for (id, n) in nodes {
        for (phase, entry) in u.unused(id) {
            if !any {
                h.raw("<div class=\"callout\"><p><span class=\"badge\">No observed use</span> ")
                    .raw("No contact of the hub's jobs placed under these caps matched these ")
                    .raw("entries:</p><ul class=\"access\">");
                any = true;
            }
            let since = u
                .since_day
                .get(id.as_str())
                .copied()
                .filter(|d| *d > window);
            let used = u
                .entries
                .get(&(id.clone(), phase, entry.to_string()))
                .and_then(|e| e.last_day);
            let c = u
                .coverage
                .get(&(id.clone(), phase))
                .copied()
                .unwrap_or_default();
            h.raw("<li><a href=\"/node/")
                .text(id)
                .raw("\"><strong>")
                .node(&n.hostname)
                .raw("</strong></a> · ")
                .raw(if phase == "build" { "Build" } else { "Run" })
                .raw(" · <code>")
                .text(entry)
                .raw("</code> · ");
            match since {
                Some(day) => h
                    .raw("no observed use since ")
                    .text(super::observed::date(day))
                    .raw(", its first job kept under these caps"),
                None => h.raw("no observed use in 30 days"),
            };
            match used {
                Some(day) => h.raw(" · last used ").text(super::observed::date(day)),
                None => h.raw(" · not seen in the history kept"),
            };
            h.raw(" · ")
                .text(c.complete)
                .raw(" of ")
                .text(c.ran)
                .raw(" jobs placed on it under these caps reported this phase completely");
            if let Some(n) = u.unreported.get(id.as_str()).filter(|n| **n > 0) {
                h.raw(", ").text(jobs_text(*n)).raw(" sent no report");
            }
            h.raw("</li>");
        }
    }
    if !any {
        return;
    }
    h.raw("</ul><p class=\"sub\">Hub-observed jobs only; other workloads on the node may use ")
        .raw("them, its gitlab-runner's jobs among them.");
    if u.capped {
        h.raw(" The job history was read only in part.");
    }
    h.raw(" No reported use does not prove an entry unnecessary; nothing is removed ")
        .raw("automatically.</p></div>");
}

/// One rule's row of the list.
fn rule_row(h: &mut Html, r: &EgressRuleRow, l: &Listing) {
    h.raw("<tr><td><a href=\"")
        .text(rule_href(&r.name))
        .raw("\"><strong>")
        .text(rule_name(r))
        .raw("</strong></a>");
    let unused = l.used.rule_use.unused(&r.name).len();
    if unused > 0 {
        h.raw("<div class=\"sub\">")
            .text(unused)
            .raw(if unused == 1 { " entry" } else { " entries" })
            .raw(" with no observed use in 30 days</div>");
    }
    h.raw("</td><td>")
        .text(applies_to(r))
        .raw("</td><td>")
        .text(phase_summary(&r.run))
        .raw("</td><td>")
        .text(phase_summary(&r.build))
        .raw("</td><td>");
    mode_badge(h, r.mode);
    h.raw("</td><td>")
        .text(jobs_summary(
            r.mode,
            l.used
                .recent
                .rules
                .get(&r.name)
                .copied()
                .unwrap_or_default(),
        ))
        .raw("</td></tr>");
}

pub(super) fn mode_badge(h: &mut Html, mode: RuleMode) {
    h.raw(match mode {
        RuleMode::Enforce => "<span class=\"badge ok\">Enforce</span>",
        RuleMode::DryRun => "<span class=\"badge warn\">Dry-run</span>",
    });
}

/// `1 job`, `2 jobs`.
fn jobs_text(n: u64) -> String {
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} job{plural}")
}

/// The recent jobs a rule applied to: `42 jobs`; for a dry-run rule `3 jobs · 1 would block`.
fn jobs_summary(mode: RuleMode, n: RuleJobs) -> String {
    match mode {
        RuleMode::Enforce => jobs_text(n.enforced),
        RuleMode::DryRun if n.dry_run == 0 => "no jobs".to_string(),
        RuleMode::DryRun => format!("{} · {} would block", jobs_text(n.dry_run), n.would_block),
    }
}

/// A phase in a few words: `Unrestricted by this rule`, `No external access`,
/// `corp.example.com + 1 IP range`, `3 domains`.
pub(super) fn phase_summary(p: &HubPhase) -> String {
    let HubPhase::Allow { names, ips } = p else {
        return match p {
            HubPhase::Unrestricted => "Unrestricted by this rule".to_string(),
            _ => "A kind this hub does not know".to_string(),
        };
    };
    let plural = |n: usize, one: &str, many: &str| match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    };
    let mut parts = Vec::new();
    match names.as_slice() {
        [] => {}
        [one] => parts.push(one.clone()),
        many => parts.push(plural(many.len(), "domain", "domains")),
    }
    match ips.as_slice() {
        [] => {}
        [one] if names.is_empty() => parts.push(one.clone()),
        many => parts.push(plural(many.len(), "IP range", "IP ranges")),
    }
    if parts.is_empty() {
        return "No external access".to_string();
    }
    parts.join(" + ")
}

/// The phases as a page names them.
const PHASES: [(&str, &str); 2] = [
    ("run", "Run: job commands and services"),
    ("build", "Build: image build RUN steps"),
];

/// Rule `r`'s page: what it selects, how, and each phase's entries.
fn rule_page(l: &Listing, r: &EgressRuleRow, auth: &Auth) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, Tab::Rules, None);
    live_start(&mut h, Some(&r.name));
    rule_results(&mut h, l, r);
    live_end(&mut h);
    if auth.session.role >= Role::Operator {
        super::editor::rule_forms(&mut h, r, &l.gitlabs, auth);
    }
    h
}

/// Rule `r`'s page but its forms: how the rules stand, what it selects, how, and each phase's
/// entries with their use.
fn rule_results(h: &mut Html, l: &Listing, r: &EgressRuleRow) {
    state_callout(h, &l.rules);
    h.raw("<h2>").text(rule_name(r));
    if is_fallback(r) {
        h.raw(" <span class=\"sub\">(<code>default</code>)</span>");
    }
    h.raw("</h2><p><a href=\"")
        .raw(PATH)
        .raw("\">Every rule</a></p><table class=\"kv\"><tbody>");
    pages::kv(h, "Applies to", &applies_to(r));
    pages::kv_html(h, "Mode", &{
        let mut b = Html::new();
        mode_badge(&mut b, r.mode);
        b.raw(match r.mode {
            RuleMode::Enforce => "",
            RuleMode::DryRun => {
                " <span class=\"sub\">reports what it would block, and blocks nothing</span>"
            }
        });
        b
    });
    pages::kv(
        h,
        "Last 7 days",
        &jobs_summary(
            r.mode,
            l.used
                .recent
                .rules
                .get(&r.name)
                .copied()
                .unwrap_or_default(),
        ),
    );
    pages::kv_html(h, "Changed", &{
        let mut b = Html::new();
        b.text(format!("version {} by {}, ", r.version, r.updated_by));
        pages::at(&mut b, r.updated_at);
        b
    });
    h.raw("</tbody></table>");
    for ((key, label), phase) in PHASES.iter().zip([&r.run, &r.build]) {
        h.raw("<section><h3>").raw(label).raw("</h3>");
        phase_detail(h, phase);
        entries_use(h, &l.used.rule_use, r, key, phase);
        h.raw("</section>");
    }
    super::observed::caution(h, &l.used.rule_use);
}

/// A phase's choice and, when it lists destinations, each dimension's entries: `None` for an
/// empty one.
fn phase_detail(h: &mut Html, p: &HubPhase) {
    let HubPhase::Allow { names, ips } = p else {
        h.raw("<p>").text(phase_summary(p)).raw("</p>");
        return;
    };
    if names.is_empty() && ips.is_empty() {
        h.raw("<p>Allow none: no external access.</p>");
        return;
    }
    h.raw("<p>Allow listed destinations:</p><table class=\"kv\"><tbody>");
    for (label, list) in [("Domains", names), ("IP ranges", ips)] {
        let mut b = Html::new();
        if list.is_empty() {
            b.raw("None");
        }
        for (i, e) in list.iter().enumerate() {
            if i > 0 {
                b.raw(", ");
            }
            b.raw("<code>").text(e).raw("</code>");
        }
        pages::kv_html(h, label, &b);
    }
    h.raw("</tbody></table>");
}

/// Each entry of rule `r`'s phase `key` with its use in the last 30 days, and the phase's
/// coverage among the jobs the rule applies to.
fn entries_use(h: &mut Html, u: &RuleUse, r: &EgressRuleRow, key: &'static str, p: &HubPhase) {
    let HubPhase::Allow { names, ips } = p else {
        return;
    };
    if names.is_empty() && ips.is_empty() {
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>entry</th><th class=\"num\">jobs, last 30 ")
        .raw("days</th><th>use</th></tr></thead><tbody>");
    for e in names.iter().chain(ips) {
        let used = u
            .entries
            .get(&(r.name.clone(), key, e.clone()))
            .cloned()
            .unwrap_or_default();
        h.raw("<tr><td><code>")
            .text(e)
            .raw("</code></td><td class=\"num\">")
            .text(used.jobs)
            .raw("</td><td>");
        match u.standing(&r.name, key, e) {
            Standing::Used => {
                h.raw("Used");
            }
            Standing::Unused => {
                h.raw("<span class=\"badge\">No observed use in 30 days</span> ");
            }
            Standing::NoEvidence => {
                h.raw("<span class=\"badge warn\">Insufficient evidence</span> ");
            }
        }
        h.raw(" <span class=\"sub\">")
            .text(super::observed::use_text(u, &r.name, key, e))
            .raw("</span></td></tr>");
    }
    h.raw("</tbody></table>");
    if let Some(n) = u.unreported.get(&r.name).filter(|n| **n > 0) {
        h.raw("<p class=\"sub\">")
            .text(n)
            .raw(" jobs it applies to sent no report in the last 30 days.</p>");
    }
}
