//! `/egress?tab=rules`: the Egress page's *Rules* tab, for viewers and operators alike — the
//! hub's egress rules ([`crate::egress::rules`]), each with the jobs it selects in plain words,
//! what each phase may reach under it, its mode, and the recent jobs placed under it; the
//! Fallback listed apart. With `[jobs] egress_rules` off the tab says that saved rules restrict
//! nothing. Each rule has a page of its own, `/egress?tab=rules&rule=<name>`, listing its
//! entries; there operators change or remove it, and on `/egress?tab=rules&new=rule` add one,
//! through Preview → Save ([`super::editor`]).
//!
//! Rule names and entries are operators' to choose, checked as a node checks its own lists;
//! they are escaped as any text.

use std::sync::Arc;

use anyhow::Result;
use hyper::{Response, StatusCode};
use vk_hub_proto::egress::HubPhase;

use super::super::html::Html;
use super::super::jobs::percent_encode;
use super::super::pages;
use super::super::{Auth, Body, Ui, access, blocking, decode_form, field, fleet, message, page};
use super::{Caches, PATH as EGRESS, Tab, capital};
use crate::egress::aggregates::Aggregates;
use crate::egress::rules::{self as ops, RECENT_SCAN, RuleJobs, Rules};
use crate::server::Hub;
use crate::store::{DEFAULT_RULE, EgressRuleRow, Role, RuleMode};

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
    /// The recent jobs.
    used: Arc<Aggregates>,
}

fn listing(hub: &Hub, caches: &Caches) -> Result<Listing> {
    let rules = ops::list(hub)?;
    Ok(Listing {
        used: caches.aggregates.get(hub, &rules, crate::now_secs())?,
        rules,
        gitlabs: hub.db.gitlabs()?.into_iter().map(|(n, _)| n).collect(),
    })
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
    tab_results(&mut h, l);
    h
}

/// The tab's list: how the rules stand, the rules and the Fallback.
fn tab_results(h: &mut Html, l: &Listing) {
    state_callout(h, &l.rules);
    let (fallback, rules): (Vec<&EgressRuleRow>, Vec<&EgressRuleRow>) =
        l.rules.rules.iter().partition(|r| is_fallback(r));
    if rules.is_empty() && fallback.is_empty() {
        h.raw("<p class=\"empty\">no rules yet</p>");
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
}

/// One rule's row of the list.
fn rule_row(h: &mut Html, r: &EgressRuleRow, l: &Listing) {
    h.raw("<tr><td><a href=\"")
        .text(rule_href(&r.name))
        .raw("\"><strong>")
        .text(rule_name(r))
        .raw("</strong></a></td><td>")
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
    rule_results(&mut h, l, r);
    if auth.session.role >= Role::Operator {
        super::editor::rule_forms(&mut h, r, &l.gitlabs, auth);
    }
    h
}

/// Rule `r`'s page but its forms: how the rules stand, what it selects, how, and each phase's
/// entries.
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
    for ((_, label), phase) in PHASES.iter().zip([&r.run, &r.build]) {
        h.raw("<section><h3>").raw(label).raw("</h3>");
        phase_detail(h, phase);
        h.raw("</section>");
    }
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
