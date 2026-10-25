//! `/egress?tab=test`: the Egress page's *Test a job*, for viewers and operators alike — what a
//! job would get, and why (`docs/fleet-design.md`, *Rules on the page*): for a recent job, or a
//! GitLab instance, project, ref and protection, and optionally a node and a destination, each
//! layer apart — the node's cap, the hub's rules (those enforced, the dry-run candidates,
//! whether the Fallback applies), the job's own lists and its services' when its spec is
//! kept — then the result per phase and VM, and for a destination which layer decides it: each
//! layer evaluated on its own, as the node checks it, the result allowing only what every one
//! allows. Never one flattened list. A recent job shows the rules it was dispatched under beside
//! those that would apply now.
//!
//! The node's layer is its caps as it reports them in its inventory, evaluated per phase, a job's
//! entries they or the hub's rules leave nothing of named, as the node warns of them; a node
//! that does not report them, or none chosen, leaves it unevaluated, and the result says so. A
//! job's ref, project and variables are its submitter's to choose: each goes through
//! [`Html::node`].

use anyhow::Result;
use hyper::Response;
use vk_hub_proto::egress::{
    DryRunRule, EgressCaps, EgressPhase, HubEgress, HubPhase, NodeEgressCaps,
};
use vk_hub_proto::job::{CiJob, JobSpec};

use super::super::html::Html;
use super::super::jobs::percent_encode;
use super::super::{Auth, Body, Ui, blocking, decode_form, field, fleet, page};
use super::rules::{cap_summary, phase_summary, rule_href};
use super::{PATH as EGRESS, Tab, capital};
use crate::egress::cap_use::listed;
use crate::egress::matching::{Dest, Verdict, dns_refused, verdict};
use crate::egress::narrowing::{self, Declared, Narrowing, Says, Stand};
use crate::egress::rules::{self as ops, Rules, claims_of};
use crate::store::{DEFAULT_RULE, EgressRuleRow, JobRow, NodeRow, resolve_egress};
use crate::subject::JobClaims;

/// The tab.
pub(super) const PATH: &str = "/egress?tab=test";

/// The query's value of `tab` that asks for this tab.
const TAB: &str = "test";

/// The latest jobs the tab offers to test.
const OFFERED: usize = 10;

/// What is tested: a job by ID, or claims typed in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Query {
    job: String,
    gitlab: String,
    project: String,
    project_id: String,
    git_ref: String,
    /// `protected`, or anything else for unprotected.
    protection: String,
    node: String,
    destination: String,
}

impl Query {
    /// `/egress?tab=test[&job=…|&gitlab=…&project=…&project_id=…&ref=…&protection=…]
    /// [&node=…][&destination=…]`; `None` for another tab.
    pub(super) fn of(query: Option<&str>) -> Option<Query> {
        let query = decode_form(query.unwrap_or("").as_bytes());
        if field(&query, "tab") != Some(TAB) {
            return None;
        }
        let get = |name: &str| field(&query, name).unwrap_or("").trim().to_string();
        Some(Query {
            job: get("job"),
            gitlab: get("gitlab"),
            project: get("project"),
            project_id: get("project_id"),
            git_ref: get("ref"),
            protection: get("protection"),
            node: get("node"),
            destination: get("destination"),
        })
    }

    fn asks(&self) -> bool {
        !(self.job.is_empty()
            && self.gitlab.is_empty()
            && self.project.is_empty()
            && self.project_id.is_empty()
            && self.git_ref.is_empty())
    }

    /// The claims typed in; `None` with no GitLab instance, as an older hub recorded the jobs
    /// of an API key bound to none.
    fn claims(&self) -> Option<JobClaims> {
        (!self.gitlab.is_empty()).then(|| JobClaims {
            gitlab: self.gitlab.clone(),
            project_id: self.project_id.parse().unwrap_or_default(),
            project_path: self.project.clone(),
            git_ref: self.git_ref.clone(),
            protected: self.protection == "protected",
            pipeline_id: 0,
        })
    }
}

/// `/egress?tab=test&job=<id>`: job `id` tested, as an attribute's value.
pub(super) fn job_href(id: &str) -> String {
    format!("{PATH}&job={}", percent_encode(id))
}

/// A job tested, with its spec when it is kept.
struct Tested {
    id: String,
    row: JobRow,
    spec: Option<CiJob>,
}

/// What the tab shows.
struct Listing {
    rules: Rules,
    gitlabs: Vec<String>,
    nodes: Vec<(String, NodeRow)>,
    latest: Vec<(String, JobRow)>,
    /// The job asked for, `None` when it is not kept.
    job: Option<Tested>,
}

fn listing(hub: &crate::server::Hub, q: &Query) -> Result<Listing> {
    let job = match vk_hub_proto::valid_id(&q.job) {
        true => match hub.db.job(&q.job)? {
            Some(row) => {
                let spec = hub
                    .db
                    .job_spec(&q.job)?
                    .and_then(|b| serde_json::from_slice::<JobSpec>(&b).ok())
                    .map(|JobSpec::GitlabCi(ci)| ci);
                Some(Tested {
                    id: q.job.clone(),
                    row,
                    spec,
                })
            }
            None => None,
        },
        false => None,
    };
    let mut nodes = hub.db.nodes()?;
    nodes.sort_by(|a, b| (&a.1.hostname, &a.0).cmp(&(&b.1.hostname, &b.0)));
    Ok(Listing {
        rules: ops::list(hub)?,
        gitlabs: hub.db.gitlabs()?.into_iter().map(|(n, _)| n).collect(),
        nodes,
        latest: hub.db.jobs(OFFERED)?,
        job,
    })
}

/// `GET /egress?tab=test…` ([`Query::of`]).
pub(super) async fn get(q: Query, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let (hub, wanted) = (ui.hub.clone(), q.clone());
    let l = blocking(move || listing(&hub, &wanted)).await?;
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, Tab::Test, None);
    h.raw("<p class=\"sub\">What a job would get, and why: each layer apart, then the result ")
        .raw("per phase. A destination is reachable only if every layer allows it.</p>");
    form(&mut h, &q, &l);
    if q.asks() {
        result(&mut h, &q, &l);
    }
    Ok(page(fleet::layout("Egress", EGRESS, auth, &h)))
}

/// The form, a plain GET: a job, or what it would claim; a node; a destination.
fn form(h: &mut Html, q: &Query, l: &Listing) {
    let input = |h: &mut Html, label: &str, name: &str, value: &str, hint: &str| {
        h.raw("<label>")
            .text(label)
            .raw(" <input type=\"text\" name=\"")
            .text(name)
            .raw("\" autocomplete=\"off\" placeholder=\"")
            .text(hint)
            .raw("\" value=\"")
            .text(value)
            .raw("\"></label>");
    };
    h.raw("<form class=\"wide\" method=\"get\" action=\"")
        .raw(EGRESS)
        .raw("\"><input type=\"hidden\" name=\"tab\" value=\"")
        .raw(TAB)
        .raw("\">");
    input(h, "Job ID", "job", &q.job, "a recent job");
    h.raw("<fieldset><legend>Or what a job would claim</legend><label>GitLab <select ")
        .raw("name=\"gitlab\"><option value=\"\">None: a job of no GitLab instance</option>");
    for g in &l.gitlabs {
        h.raw("<option value=\"").text(g).raw("\"");
        if *g == q.gitlab {
            h.raw(" selected");
        }
        h.raw(">").text(g).raw("</option>");
    }
    h.raw("</select></label>");
    input(h, "Project path", "project", &q.project, "wab/api");
    input(h, "Project ID", "project_id", &q.project_id, "1172");
    input(h, "Branch or tag", "ref", &q.git_ref, "main");
    h.raw("<label>Protection <select name=\"protection\">");
    for (value, label) in [("protected", "Protected"), ("", "Unprotected")] {
        h.raw("<option value=\"").raw(value).raw("\"");
        if q.protection == value {
            h.raw(" selected");
        }
        h.raw(">").raw(label).raw("</option>");
    }
    h.raw("</select></label></fieldset><label>Node <select name=\"node\">")
        .raw("<option value=\"\">Any</option>");
    for (id, n) in &l.nodes {
        h.raw("<option value=\"").text(id).raw("\"");
        if *id == q.node {
            h.raw(" selected");
        }
        h.raw(">").node(&n.hostname).raw("</option>");
    }
    h.raw("</select></label>");
    input(
        h,
        "Destination",
        "destination",
        &q.destination,
        "partner.example.net or 10.0.0.1:443",
    );
    h.raw(" <button class=\"primary\">Test</button></form>");
    if !l.latest.is_empty() {
        h.raw("<p class=\"sub\">Recent jobs: ");
        for (i, (id, j)) in l.latest.iter().enumerate() {
            if i > 0 {
                h.raw(" · ");
            }
            h.raw("<a href=\"")
                .text(job_href(id))
                .raw("\">")
                .node(j.name.as_deref().unwrap_or(&j.title))
                .raw("</a>");
        }
        h.raw("</p>");
    }
}

/// The phases tested, as a page names them.
const PHASES: [(EgressPhase, &str); 2] = [(EgressPhase::Run, "Run"), (EgressPhase::Build, "Build")];

/// What was tested and each layer apart, then the result per phase.
fn result(h: &mut Html, q: &Query, l: &Listing) {
    if !q.job.is_empty() && l.job.is_none() {
        h.raw("<p class=\"callout warn\">There is no such job in the history.</p>");
        return;
    }
    let claims = match &l.job {
        Some(t) => claims_of(&t.row),
        None => q.claims(),
    };
    let dest = match q.destination.as_str() {
        "" => None,
        text => match Dest::parse(text) {
            Some(d) => Some(d),
            None => {
                h.raw("<p class=\"callout warn\">")
                    .node(text)
                    .raw(" is neither a DNS name nor an IPv4 address, with or without its ")
                    .raw("port.</p>");
                return;
            }
        },
    };
    let layer = resolve_egress(&l.rules.rules, claims.as_ref());
    h.raw("<section><h2>Tested as</h2><p>");
    match &claims {
        Some(c) => {
            h.node(&c.project_path)
                .raw(" on ")
                .text(&c.gitlab)
                .raw(" (project ")
                .text(c.project_id)
                .raw("), ")
                .node(if c.git_ref.is_empty() {
                    "no ref"
                } else {
                    &c.git_ref
                })
                .raw(if c.protected {
                    ", protected"
                } else {
                    ", unprotected"
                });
        }
        None => {
            h.raw("A job of no GitLab instance: only the Fallback applies to it.");
        }
    }
    if let Some(t) = &l.job {
        h.raw(" · job <a href=\"")
            .raw(super::super::jobs::DETAIL_PREFIX)
            .text(&t.id)
            .raw("\">")
            .node(t.row.name.as_deref().unwrap_or(&t.row.title))
            .raw("</a>");
        if t.row.protected.is_none() && claims.is_some() {
            h.raw(" (GitLab did not report its protection: read as unprotected)");
        }
    }
    if let Some(d) = &dest {
        h.raw(" · destination <code>").text(d.text()).raw("</code>");
    }
    h.raw("</p></section><ol class=\"layers\">");
    let caps = caps(q, l);
    node_layer(h, q, l);
    hub_layer(h, l, &layer);
    job_layer(h, l, &layer, caps);
    h.raw("</ol>");
    outcome(h, l, &layer, caps, dest.as_ref());
}

/// The node tested: the one chosen, else the one the job ran on.
fn node<'a>(q: &Query, l: &'a Listing) -> Option<&'a (String, NodeRow)> {
    l.nodes.iter().find(|(id, _)| *id == q.node).or_else(|| {
        let ran = l.job.as_ref().and_then(|t| t.row.node.as_ref())?;
        l.nodes.iter().find(|(id, _)| id == ran)
    })
}

/// The caps of the node tested, when it reports them.
fn caps<'a>(q: &Query, l: &'a Listing) -> Option<&'a EgressCaps> {
    node(q, l).and_then(|(_, n)| listed(n))
}

/// A cap's phase, `phase`.
fn cap_phase(c: &EgressCaps, phase: EgressPhase) -> Option<&HubPhase> {
    match phase {
        EgressPhase::Run => Some(&c.run),
        EgressPhase::Build => Some(&c.build),
        EgressPhase::Other => None,
    }
}

fn node_layer(h: &mut Html, q: &Query, l: &Listing) {
    h.raw("<li><strong>Node cap</strong>");
    let Some((id, n)) = node(q, l) else {
        h.raw(": no node chosen: node limits not evaluated.</li>");
        return;
    };
    h.raw(" (<a href=\"/node/")
        .text(id)
        .raw("\">")
        .node(&n.hostname)
        .raw("</a>)");
    let enforces = n.inventory.as_ref().is_some_and(|i| i.egress_rules);
    h.raw(if enforces {
        ": it enforces the hub's rules."
    } else if l.rules.enabled {
        ": it does not enforce the hub's rules, so it takes no placed job while they are on."
    } else {
        ": it does not enforce the hub's rules."
    });
    let reported = n.inventory.as_ref().and_then(|i| i.egress_caps.as_ref());
    let c = match reported {
        Some(NodeEgressCaps::Listed(c)) => c,
        Some(NodeEgressCaps::TooLarge) => {
            h.raw(" <span class=\"sub\">Its caps are too large to report: node limits not ")
                .raw("evaluated.</span></li>");
            return;
        }
        Some(NodeEgressCaps::Other) => {
            h.raw(" <span class=\"sub\">It reports its caps in a form this hub cannot read: ")
                .raw("node limits not evaluated.</span></li>");
            return;
        }
        None => {
            h.raw(" <span class=\"sub\">It does not report its caps: node limits not ")
                .raw("evaluated. A newer <code>vk</code> reports them.</span></li>");
            return;
        }
    };
    h.raw("<ul class=\"access\">");
    for (phase, label) in PHASES {
        if let Some(p) = cap_phase(c, phase) {
            h.raw("<li>").raw(label).raw(": ").text(cap_summary(p));
            if phase == EgressPhase::Run && c.run_dry_run {
                h.raw(" <span class=\"badge warn\">Dry-run</span> it reports, and blocks nothing");
            }
            h.raw("</li>");
        }
    }
    h.raw("</ul>");
    if let Some(t) = l.job.as_ref().filter(|t| t.row.node.as_deref() == Some(id)) {
        match &t.row.egress_caps {
            Some(f) if *f == c.fingerprint => {
                h.raw("<p class=\"sub\">The caps the job was placed under.</p>");
            }
            Some(_) => {
                h.raw("<p class=\"sub\">The job was placed under other caps: they changed ")
                    .raw("since.</p>");
            }
            None => {}
        }
    }
    h.raw("</li>");
}

/// The rules of `l` named `name`.
fn rule<'a>(l: &'a Listing, name: &str) -> Option<&'a EgressRuleRow> {
    l.rules.rules.iter().find(|r| r.name == name)
}

/// A rule's name, linked to its page; the Fallback as such.
fn linked(h: &mut Html, name: &str) {
    h.raw("<a href=\"")
        .text(rule_href(name))
        .raw("\">")
        .text(if name == DEFAULT_RULE {
            "Fallback"
        } else {
            name
        })
        .raw("</a>");
}

fn names(h: &mut Html, list: &[String]) {
    for (i, n) in list.iter().enumerate() {
        if i > 0 {
            h.raw(", ");
        }
        linked(h, n);
    }
}

fn hub_layer(h: &mut Html, l: &Listing, layer: &HubEgress) {
    h.raw("<li><strong>Hub rules</strong>");
    if !l.rules.enabled {
        h.raw(" <span class=\"badge\">Off</span> <span class=\"sub\">Not enforced: as the ")
            .raw("saved rules would apply once <code>[jobs] egress_rules = true</code>.</span>");
    }
    h.raw("<p>Under current rules: ");
    let fallback = layer.rules == [DEFAULT_RULE];
    match layer.rules.as_slice() {
        [] => {
            h.raw("no rule selects it and no Fallback is enforced, so it may reach nothing");
        }
        _ if fallback => {
            h.raw("no enforced rule selects it");
        }
        rules => {
            h.raw("enforced ");
            names(h, rules);
        }
    }
    let dry: Vec<String> = layer.dry_run.iter().map(|d| d.rule.clone()).collect();
    if !dry.is_empty() {
        h.raw(" · dry-run candidates ");
        names(h, &dry);
    }
    h.raw(if fallback {
        " · Fallback used"
    } else {
        " · Fallback not used"
    })
    .raw(".</p><ul class=\"access\">");
    for (phase, label) in PHASES {
        if let Some(p) = layer.phase(phase) {
            h.raw("<li>")
                .raw(label)
                .raw(": ")
                .text(phase_summary(p))
                .raw("</li>");
        }
    }
    h.raw("</ul>");
    if let Some(t) = &l.job {
        h.raw("<p>As dispatched: ");
        match (&t.row.egress_rules, t.row.started_at) {
            (Some(a), _) => {
                h.text(crate::egress::rules_applied_text(a));
            }
            (None, Some(_)) => {
                h.raw("placed with hub rules off, under its node's cap and its own lists ")
                    .raw("alone");
            }
            (None, None) => {
                h.raw("not placed");
            }
        }
        h.raw(".</p>");
    }
    h.raw("</li>");
}

/// What a filter declares, in words: `MICROVM_EGRESS_ALLOW_NAME corp.example.com; IP ranges
/// not declared`.
fn declared_text(n: &Narrowing) -> String {
    let one = |(variable, d): &(&str, Declared), what: &str| match d {
        Declared::Absent => format!("{what} not declared"),
        Declared::Hidden => format!("{variable} hidden in the stored spec"),
        Declared::Expands => format!("{variable} names other variables, expanded on the node"),
        Declared::List(list) if list.is_empty() => format!("{variable} empty: none"),
        Declared::List(list) => format!("{variable} {}", list.join(", ")),
        Declared::Invalid(list) => format!("{variable} invalid: {}", list.join(", ")),
    };
    format!("{}; {}", one(&n.names, "domains"), one(&n.ips, "IP ranges"))
}

/// The VMs of a phase whose filters differ: the job's, then in the run phase each service that
/// declares its own, by the name it answers to.
fn vms(ci: Option<&CiJob>, phase: EgressPhase) -> Vec<Option<(String, Narrowing)>> {
    let mut out = vec![None];
    if phase == EgressPhase::Run
        && let Some(ci) = ci
    {
        out.extend(narrowing::services(ci).into_iter().map(Some));
    }
    out
}

/// The entries a job's filter of `phase`, or a service's, declares that a layer above leaves
/// nothing of, in words, each with that layer: the node's `cap`, the hub's rules `hub` when
/// they are on, then for a service the job's own filter. The node keeps them and warns of them.
fn unreachable_text(
    cap: Option<&HubPhase>,
    hub: Option<&HubPhase>,
    ci: &CiJob,
    phase: EgressPhase,
) -> Vec<String> {
    let job = narrowing::narrowing(&ci.variables, phase);
    let mut out = Vec::new();
    for vm in vms(Some(ci), phase) {
        let (who, filter, mut above) = match &vm {
            None => (String::new(), job.as_ref(), Vec::new()),
            Some((service, n)) => (
                format!("service {service}'s "),
                Some(n),
                job.as_ref()
                    .and_then(Narrowing::as_phase)
                    .map(|p| vec![("the job's own filter", p)])
                    .unwrap_or_default(),
            ),
        };
        let Some(filter) = filter else {
            continue;
        };
        let mut layers: Vec<(&str, HubPhase)> = Vec::new();
        layers.extend(cap.map(|p| ("the node's cap", p.clone())));
        layers.extend(hub.map(|p| ("the hub's rules", p.clone())));
        layers.append(&mut above);
        let mut seen: Vec<&str> = Vec::new();
        for (layer, p) in &layers {
            for (v, e) in filter.unreachable(p) {
                if !seen.contains(&e) {
                    seen.push(e);
                    out.push(format!("{who}{v} {e} (outside {layer})"));
                }
            }
        }
    }
    out
}

fn job_layer(h: &mut Html, l: &Listing, layer: &HubEgress, caps: Option<&EgressCaps>) {
    h.raw("<li><strong>Job restriction</strong>");
    let Some(t) = &l.job else {
        h.raw(": not known: its CI configuration decides it.</li>");
        return;
    };
    let Some(ci) = &t.spec else {
        h.raw(": not known: the job's spec is no longer kept.</li>");
        return;
    };
    let mut any = false;
    h.raw("<ul class=\"access\">");
    for (phase, label) in PHASES {
        if let Some(n) = narrowing::narrowing(&ci.variables, phase).filter(Narrowing::declares) {
            any = true;
            h.raw("<li>")
                .raw(label)
                .raw(": ")
                .node(&declared_text(&n))
                .raw("</li>");
        }
    }
    let services = narrowing::services(ci);
    for (service, n) in &services {
        any = true;
        h.raw("<li>Service ")
            .node(service)
            .raw(", run: ")
            .node(&declared_text(n))
            .raw("</li>");
    }
    h.raw("</ul>");
    if !any {
        h.raw("<p>None declared.</p>");
    }
    let (run, build) = (
        invalid_text(ci, EgressPhase::Run),
        invalid_text(ci, EgressPhase::Build),
    );
    if !run.is_empty() {
        h.raw("<p class=\"callout warn\">An invalid entry fails the job before it reaches ")
            .raw("anything: ")
            .node(&run.join(", "))
            .raw(".</p>");
    }
    if !build.is_empty() {
        h.raw("<p class=\"callout warn\">An invalid build-phase entry fails the job if it ")
            .raw("builds an image: ")
            .node(&build.join(", "))
            .raw(".</p>");
    }
    if narrowing::dry_run_requested(&ci.variables) {
        h.raw("<p class=\"sub\"><code>MICROVM_EGRESS_DRY_RUN</code> asks for a dry-run run ")
            .raw("phase, which the node grants only where its cap restricts no run phase.</p>");
    }
    if !services.is_empty() {
        h.raw("<p class=\"sub\">").raw(SERVICES_OWN).raw("</p>");
    }
    for (phase, label) in PHASES {
        let cap = caps.and_then(|c| cap_phase(c, phase));
        let warned = unreachable_text(cap, layer.phase(phase), ci, phase);
        if warned.is_empty() {
            continue;
        }
        h.raw("<p class=\"callout warn\">")
            .raw(label)
            .raw(": ")
            .node(&warned.join(", "))
            .raw(". The node keeps them and warns of them; that layer refuses what they list")
            .raw(if l.rules.enabled {
                " when the job runs.</p>"
            } else {
                " when the job runs, a hub rule's once hub rules are on.</p>"
            });
    }
    h.raw("<p class=\"sub\">The node's cap, the hub's rules and the job's own lists are each ")
        .raw("checked on its own when the job runs: a destination is reachable only if every one ")
        .raw("allows it. Within each, a dimension not declared allows none once the other is. An ")
        .raw("invalid entry fails the job; one outside a layer above is kept, and the node warns ")
        .raw("of it.</p></li>");
}

/// The invalid entries of the job's declarations of `phase`, and in the run phase its services',
/// in words. The node checks the run phase's before the job starts, the build phase's only when
/// it builds an image.
fn invalid_text(ci: &CiJob, phase: EgressPhase) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(n) = narrowing::narrowing(&ci.variables, phase) {
        out.extend(invalid_entries(&n, ""));
    }
    if phase == EgressPhase::Run {
        for (service, n) in narrowing::services(ci) {
            out.extend(invalid_entries(&n, &format!("service {service}'s ")));
        }
    }
    out
}

/// How an invalid entry fails the job, whatever phase or VM is tested; `None` with none.
fn fails(ci: &CiJob) -> Option<&'static str> {
    if !invalid_text(ci, EgressPhase::Run).is_empty() {
        Some("The job fails: an invalid entry")
    } else if !invalid_text(ci, EgressPhase::Build).is_empty() {
        Some("The job fails if it builds an image: an invalid entry")
    } else {
        None
    }
}

/// `n`'s invalid entries, each with its variable, `who` before it.
fn invalid_entries(n: &Narrowing, who: &str) -> Vec<String> {
    [&n.ips, &n.names]
        .into_iter()
        .filter_map(|(variable, d)| match d {
            Declared::Invalid(list) => Some(format!("{who}{variable} {}", list.join(" "))),
            _ => None,
        })
        .collect()
}

/// What a restricting layer says of an address on DNS's port, which it refuses whatever it
/// lists.
const DNS_REFUSED: &str = "lookups go only to the node's resolver";

/// How a layer's phase stands for a destination, with the rules whose entries allow it.
fn hub_says(l: &Listing, layer: &HubEgress, p: &HubPhase, phase: EgressPhase, d: &Dest) -> String {
    match verdict(p, d) {
        Verdict::Unrestricted => "Unrestricted".to_string(),
        Verdict::Allowed(_) => {
            let by: Vec<String> = layer
                .rules
                .iter()
                .filter_map(|name| {
                    let r = rule(l, name)?;
                    let phase = match phase {
                        EgressPhase::Build => &r.build,
                        _ => &r.run,
                    };
                    match verdict(phase, d) {
                        Verdict::Allowed(entries) => {
                            Some(format!("{} · {}", rule_label(name), entries.join(", ")))
                        }
                        Verdict::Unrestricted => {
                            Some(format!("{} · unrestricted", rule_label(name)))
                        }
                        _ => None,
                    }
                })
                .collect();
            format!("Allowed by {}", by.join("; "))
        }
        Verdict::ByNameOnly => {
            "Not allowed by address: only if a lookup of a listed name resolved to it".to_string()
        }
        Verdict::Outside if dns_refused(d) => format!("Blocked by hub rules: {DNS_REFUSED}"),
        Verdict::Outside => "Blocked by hub rules".to_string(),
    }
}

/// A dry-run candidate's layer of `phase`.
fn dry_phase(d: &DryRunRule, phase: EgressPhase) -> Option<&HubPhase> {
    match phase {
        EgressPhase::Run => Some(&d.run),
        EgressPhase::Build => Some(&d.build),
        EgressPhase::Other => None,
    }
}

fn rule_label(name: &str) -> &str {
    if name == DEFAULT_RULE {
        "Fallback"
    } else {
        name
    }
}

/// What a node's cap says of a destination, in words, and how it stands for it, which in a
/// dry-run run phase is never refusing.
fn cap_says(c: &EgressCaps, phase: EgressPhase, d: &Dest) -> (String, Stand) {
    let Some(p) = cap_phase(c, phase) else {
        return ("not evaluated".to_string(), Stand::Unknown);
    };
    let dry = phase == EgressPhase::Run && c.run_dry_run;
    match verdict(p, d) {
        Verdict::Unrestricted => ("Unrestricted".to_string(), Stand::Allows),
        Verdict::Allowed(entries) => (format!("Allowed by {}", entries.join(", ")), Stand::Allows),
        Verdict::ByNameOnly if dry => (
            "Not allowed by address; dry-run, it blocks nothing".to_string(),
            Stand::Allows,
        ),
        Verdict::ByNameOnly => (
            "Not allowed by address: only if a listed name's lookup resolved to it".to_string(),
            Stand::ByName,
        ),
        Verdict::Outside if dry => (
            "Would block it; dry-run, it blocks nothing".to_string(),
            Stand::Allows,
        ),
        Verdict::Outside if dns_refused(d) => (
            format!("Blocked by the node's cap: {DNS_REFUSED}"),
            Stand::Refuses,
        ),
        Verdict::Outside => ("Blocked by the node's cap".to_string(), Stand::Refuses),
    }
}

/// What a job's or a service's filter says of a destination, in words, given the dimension's
/// name in a sentence.
fn says_text(says: &Says, dimension: &str) -> String {
    match says {
        Says::Allows(v) => format!("Allowed by {v}"),
        Says::Refuses(v) => format!("Blocked by {v}"),
        Says::Undeclared { declared, by_name } => format!(
            "Blocked: only {declared} is declared, so its VM may reach no {dimension}{}",
            if *by_name {
                " but what a declared name's lookup resolved to"
            } else {
                ""
            }
        ),
        Says::ByNameOnly(v) => {
            format!("Not listed in {v}: only if a listed name's lookup resolved to it")
        }
        Says::Dns(v) => format!("Blocked: {v} restricts it, and {DNS_REFUSED}"),
        Says::Invalid(v) => format!("Fails the job: {v} has an invalid entry"),
        Says::Unknown(v) => format!("Not known: {v} is not readable here"),
        Says::Silent => "Not restricted".to_string(),
    }
}

/// The result per phase and VM: each layer's say, then what every layer together decides.
fn outcome(
    h: &mut Html,
    l: &Listing,
    layer: &HubEgress,
    caps: Option<&EgressCaps>,
    dest: Option<&Dest>,
) {
    h.raw("<section><h2>Result</h2><table class=\"grid\"><thead><tr><th>phase</th>")
        .raw("<th>VM</th><th>node cap</th><th>hub rules</th><th>dry-run</th><th>job</th>")
        .raw("<th>service</th><th>result</th></tr></thead><tbody>");
    let spec = l.job.as_ref().and_then(|t| t.spec.as_ref());
    for (phase, label) in PHASES {
        let Some(p) = layer.phase(phase) else {
            continue;
        };
        let cap = caps.and_then(|c| cap_phase(c, phase));
        let job = spec.and_then(|ci| narrowing::narrowing(&ci.variables, phase));
        // A dry-run run phase carries what the node's cap and the job's lists refuse: the node's
        // `[egress] dry_run`, or the job's own request where the node's cap restricts no run
        // phase.
        let asked = spec.is_some_and(|ci| narrowing::dry_run_requested(&ci.variables));
        let dry = phase == EgressPhase::Run
            && caps.is_some_and(|c| c.run_dry_run || (asked && c.run == HubPhase::Unrestricted));
        let fails = spec.and_then(fails);
        for vm in vms(spec, phase) {
            h.raw("<tr><td>").raw(label).raw("</td><td>");
            match &vm {
                None => h.raw("job"),
                Some((service, _)) => h.raw("service ").node(service),
            };
            h.raw("</td><td>");
            let Some(d) = dest else {
                match (caps, cap) {
                    (Some(c), Some(cp)) => {
                        h.text(cap_summary(cp));
                        if phase == EgressPhase::Run && c.run_dry_run {
                            h.raw(" (dry-run)");
                        }
                    }
                    _ => {
                        h.raw("not evaluated");
                    }
                }
                h.raw("</td><td>").text(phase_summary(p)).raw("</td><td>");
                dry_run_summaries(h, layer, phase);
                h.raw("</td><td>");
                match (&job, spec) {
                    (Some(n), _) if n.declares() => h.node(&declared_text(n)),
                    (_, Some(_)) => h.raw("none declared"),
                    _ => h.raw("not known"),
                };
                h.raw("</td><td>");
                match &vm {
                    Some((_, n)) => h.node(&declared_text(n)),
                    None => h.raw("—"),
                };
                h.raw("</td><td>");
                let unknown: Vec<&str> = [
                    (caps.is_none(), "node limits not evaluated"),
                    (spec.is_none(), "the job's restriction is not known"),
                ]
                .into_iter()
                .filter_map(|(missing, what)| missing.then_some(what))
                .collect();
                if let Some(why) = fails {
                    h.raw("<span class=\"badge bad\">")
                        .raw(why)
                        .raw("</span></td></tr>");
                    continue;
                }
                h.raw("Reachable where every layer allows it");
                if !unknown.is_empty() {
                    h.raw("; ").text(unknown.join(", "));
                }
                h.raw("</td></tr>");
                continue;
            };
            let (cap_text, cap_stand) = match caps {
                Some(c) => cap_says(c, phase, d),
                None => ("not evaluated".to_string(), Stand::Unknown),
            };
            h.text(&cap_text).raw("</td><td>");
            h.text(hub_says(l, layer, p, phase, d)).raw("</td><td>");
            for (i, dr) in layer.dry_run.iter().enumerate() {
                if i > 0 {
                    h.raw("; ");
                }
                let allows = dry_phase(dr, phase).is_some_and(|c| verdict(c, d).allows());
                h.raw(if allows {
                    "Would be allowed if "
                } else {
                    "Would be blocked if "
                })
                .text(rule_label(&dr.rule))
                .raw(" were enforced");
            }
            let dimension = match d {
                Dest::Name(_) => "domains",
                Dest::Address(..) => "IP ranges",
            };
            // A filter's cell, how it stands, which dry-run softens, and what its refusal reads
            // as; not known where its lists are not.
            let filter = |h: &mut Html, n: Option<&Narrowing>, who: &str| -> (Stand, String) {
                let Some(n) = n else {
                    h.raw(if spec.is_some() {
                        "Not restricted"
                    } else {
                        "Not known"
                    });
                    let stand = match spec {
                        Some(_) => Stand::Allows,
                        None => Stand::Unknown,
                    };
                    return (stand, String::new());
                };
                let says = n.says(d);
                h.text(says_text(&says, dimension));
                let refusal = match &says {
                    Says::Undeclared { declared, .. } => {
                        format!("Blocked: only {who}{declared} is declared")
                    }
                    Says::Refuses(v) => format!("Blocked by {who}{v}"),
                    Says::Dns(v) => format!("Blocked by {who}{v}: {DNS_REFUSED}"),
                    Says::Invalid(v) => format!("The job fails: {who}{v} has an invalid entry"),
                    _ => String::new(),
                };
                match says.stand() {
                    // An invalid entry fails the job whatever dry-run says.
                    _ if matches!(says, Says::Invalid(_)) => (Stand::Refuses, refusal),
                    Stand::Refuses | Stand::ByName if dry => {
                        h.raw("; dry-run, it blocks nothing");
                        (Stand::Allows, refusal)
                    }
                    stand => (stand, refusal),
                }
            };
            h.raw("</td><td>");
            let (job_stand, job_refusal) = filter(h, job.as_ref(), "");
            h.raw("</td><td>");
            let (service_stand, service_refusal) = match &vm {
                Some((service, n)) => filter(h, Some(n), &format!("service {service}'s ")),
                None => {
                    h.raw("—");
                    (Stand::Allows, String::new())
                }
            };
            h.raw("</td><td>");
            let hub_verdict = verdict(p, d);
            let hub_stand = match l.rules.enabled {
                true => narrowing::phase_stand(Some(p), d),
                false => Stand::Allows,
            };
            let refusals = [
                "Blocked by the node's cap".to_string(),
                "Blocked by hub rules".to_string(),
                job_refusal,
                service_refusal,
            ];
            let decided = narrowing::every(&[cap_stand, hub_stand, job_stand, service_stand]);
            match (fails, decided) {
                (Some(why), _) => {
                    h.raw("<span class=\"badge bad\">").raw(why).raw("</span>");
                }
                (None, (Stand::Refuses, Some(i))) => {
                    h.raw("<span class=\"badge bad\">")
                        .node(refusals.get(i).map_or("Blocked", String::as_str))
                        .raw("</span>");
                }
                (None, (Stand::ByName, _)) => {
                    h.raw("<span class=\"badge warn\">Blocked unless a listed name's lookup ")
                        .raw("resolved to it</span>");
                }
                (None, (Stand::Unknown, _)) => {
                    let unknown: Vec<&str> = [
                        (cap_stand == Stand::Unknown, "the node's cap"),
                        (
                            job_stand == Stand::Unknown || service_stand == Stand::Unknown,
                            "the job's restriction",
                        ),
                    ]
                    .into_iter()
                    .filter_map(|(u, what)| u.then_some(what))
                    .collect();
                    h.raw("<span class=\"badge\">Not refused by any layer known</span> ")
                        .raw("<span class=\"sub\">")
                        .text(capital(&unknown.join(" and ")))
                        .raw(if unknown.len() == 1 { " is" } else { " are" })
                        .raw(" not known; overall reachability cannot be determined.</span>");
                }
                _ => {
                    h.raw("<span class=\"badge\">Allowed by every layer</span>");
                }
            }
            if !l.rules.enabled && matches!(hub_verdict, Verdict::Outside) {
                h.raw(" <span class=\"sub\">Hub rules on, it would be blocked by them.</span>");
            }
            h.raw("</td></tr>");
        }
    }
    h.raw("</tbody></table></section>");
}

/// Each dry-run candidate's layer of `phase`, in words.
fn dry_run_summaries(h: &mut Html, layer: &HubEgress, phase: EgressPhase) {
    for (i, dr) in layer.dry_run.iter().enumerate() {
        if i > 0 {
            h.raw("; ");
        }
        let candidate = dry_phase(dr, phase).map(phase_summary).unwrap_or_default();
        h.text(rule_label(&dr.rule)).raw(": ").text(candidate);
    }
}

/// What the page says of services declaring their own filter.
const SERVICES_OWN: &str = "A service that declares its own lists is held to them as well as to \
     the job's, each checked on its own: it may reach only what both allow. Services that \
     declare none are held to the job's alone.";
