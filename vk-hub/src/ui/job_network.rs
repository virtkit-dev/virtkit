//! A job's *Network access*, ending its record: what its node's switches blocked, or would have
//! under dry-run, its egress declarations found at fault, what it reached, and how much of
//! each phase the node recorded, from the report its node sent with its result, or of a job still
//! running the latest it sent, swapped in with the record ([`crate::egress`]). Without a report
//! it says reporting is unavailable, never that the job reached nothing. Destinations, service
//! names and declared entries are the job's or its guests' to choose: each goes through
//! [`Html::node`].

use vk_hub_proto::client::JobState;
use vk_hub_proto::egress::{EgressEntry, EgressOutcome, EgressReport};

use super::html::Html;
use super::pages;
use crate::egress::blocked::{Finding, Instances, Subject};
use crate::egress::{self, Check, Network, Summary, Tally, Tone};
use crate::store::JobRow;

/// The most rows of a list shown unfolded.
const OPEN_ROWS: usize = 20;

/// What a job's network access shows beside its report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Shown<'a> {
    /// Whether its node announces egress reports now.
    pub reports: bool,
    /// Whether the session may propose hub rules from it: an operator's.
    pub propose: bool,
    /// The hub's instances, that its project is named by
    /// ([`crate::store::Db::gitlab_instances`]).
    pub instances: Instances<&'a str>,
}

/// Job `j`'s network access, for a job that reached a node. `node` is its node's name.
pub(super) fn section(h: &mut Html, j: &JobRow, node: Option<&str>, shown: Shown<'_>) {
    let reports = shown.reports;
    let network = egress::network(j);
    if matches!(network, Network::NotRun) {
        return;
    }
    h.raw("<section class=\"job-access\"><h2>Network access</h2>");
    match network {
        Network::NotRun => {}
        Network::Pending if reports => {
            h.raw("<p class=\"sub\">Nothing reported yet: its node reports the job's egress as ")
                .raw("it runs, or when it ends.</p>");
        }
        Network::Pending => {
            unavailable(h);
            h.raw("<p>Its node does not announce egress reporting.</p>");
        }
        Network::Unavailable => {
            unavailable(h);
            h.raw("<p>No egress report is available for this job. This does not mean it made ")
                .raw("no network attempts.</p>");
        }
        Network::Reported(report) => reported(h, j, report, node, shown),
    }
    h.raw("</section>");
}

fn unavailable(h: &mut Html) {
    h.raw("<p><span class=\"badge warn\">Reporting unavailable</span></p>");
}

/// A badge of `tone`.
pub(super) fn badge(h: &mut Html, tone: Tone, text: &str, title: Option<&str>) {
    h.raw(match tone {
        Tone::Ok => "<span class=\"badge ok\"",
        Tone::Warn => "<span class=\"badge warn\"",
        Tone::Bad => "<span class=\"badge bad\"",
    });
    if let Some(title) = title {
        h.raw(" title=\"").node(title).raw("\"");
    }
    h.raw(">").node(text).raw("</span>");
}

fn reported(h: &mut Html, j: &JobRow, report: &EgressReport, node: Option<&str>, shown: Shown<'_>) {
    let summary = Summary::of(report);
    let (tone, headline) = summary.headline();
    h.raw("<p>");
    badge(h, tone, &headline, None);
    if j.state != JobState::Finished {
        h.raw(" <span class=\"sub\">so far, while the job runs</span>");
    }
    if summary.refusals > 0
        || summary.unreachable > 0
        || summary.blocked.any()
        || summary.would_block.any()
    {
        h.raw(" <a href=\"")
            .text(super::egress::subject_href(&Subject::of(j)))
            .raw("\">On the Egress page</a>");
    }
    h.raw("</p>");
    refusals(h, j, report, &summary, node);
    let at = Where {
        node,
        propose: shown.propose,
        instances: shown.instances,
    };
    denials(h, j, report, EgressOutcome::Blocked, &summary.blocked, at);
    denials(
        h,
        j,
        report,
        EgressOutcome::WouldBlock,
        &summary.would_block,
        at,
    );
    observed(h, report, &summary.observed);
    coverage(h, report);
}

/// `<details>` of a list of `rows`, open when short.
fn fold(h: &mut Html, rows: usize, open: bool) {
    h.raw(if open && rows <= OPEN_ROWS {
        "<details class=\"fold\" open><summary>"
    } else {
        "<details class=\"fold\"><summary>"
    });
}

fn refusals(
    h: &mut Html,
    j: &JobRow,
    report: &EgressReport,
    summary: &Summary,
    node: Option<&str>,
) {
    let label = match (summary.refusals, summary.unreachable) {
        (0, 0) => return,
        (0, n) => format!("Declaration warnings: {n}"),
        (n, 0) => format!("Declaration refused: {n}"),
        (n, m) => format!("Declaration refused: {n}, warnings: {m}"),
    };
    fold(h, report.refusals.len(), true);
    h.text(&label).raw("</summary>");
    if summary.refusals > 0 {
        h.raw("<p>The job failed egress validation, before its script ran.</p>");
    }
    if summary.unreachable > 0 {
        h.raw("<p>A warning is an entry the job kept that a layer above leaves nothing of: ")
            .raw("every layer is checked when the job runs, and that one refuses it.</p>");
    }
    h.raw("<ul class=\"access\">");
    for r in &report.refusals {
        h.raw("<li><a href=\"")
            .text(super::egress::row_href(j, &Finding::refusal(r)))
            .raw("\"><code>")
            .node(&r.variable)
            .raw("</code> <code>")
            .node(&r.entry)
            .raw("</code></a> · ")
            .text(egress::phase_text(r.phase))
            .raw(" · ")
            .node(&egress::vm_text(&r.source))
            .raw(": ")
            .node(&egress::refusal_reason_text(r))
            .raw("<div class=\"sub\">");
        let checks = egress::refusal_checks(r);
        if checks.is_empty() {
            h.raw("Correct this entry in the job's CI configuration.");
        } else {
            h.raw("Check ");
            for (i, c) in checks.iter().enumerate() {
                if i > 0 {
                    h.raw(", or ");
                }
                check(h, c, node);
            }
            h.raw(".");
        }
        h.raw("</div></li>");
    }
    h.raw("</ul>");
    if report.refusals_omitted > 0 {
        h.raw("<p class=\"sub\">")
            .text(report.refusals_omitted)
            .raw(" more not listed.</p>");
    }
    h.raw("</details>");
}

/// Where a denial is shown: its node's name, and whether a proposal may be made from it.
#[derive(Clone, Copy)]
struct Where<'a> {
    node: Option<&'a str>,
    propose: bool,
    instances: Instances<&'a str>,
}

fn denials(
    h: &mut Html,
    j: &JobRow,
    report: &EgressReport,
    outcome: EgressOutcome,
    tally: &Tally,
    at: Where,
) {
    let node = at.node;
    if !tally.any() {
        return;
    }
    let (label, note) = match outcome {
        EgressOutcome::WouldBlock => (
            "Would block",
            "The switch allowed these attempts in dry-run mode; the allowlist would otherwise \
             have blocked them.",
        ),
        _ => (
            "Blocked",
            "The switch blocked these attempts. Their effect on the job's result is unknown.",
        ),
    };
    // An outcome from a later peer is listed as blocked, as it is counted.
    let rows: Vec<&EgressEntry> = report
        .entries
        .iter()
        .filter(|e| match outcome {
            EgressOutcome::Blocked => {
                matches!(e.outcome, EgressOutcome::Blocked | EgressOutcome::Other)
            }
            o => e.outcome == o,
        })
        .collect();
    fold(h, rows.len(), true);
    h.raw(label)
        .raw(": ")
        .text(tally.destinations_text())
        .raw(" · ")
        .text(tally.attempts_text())
        .raw("</summary><p class=\"sub\">")
        .raw(note)
        .raw("</p><ul class=\"access\">");
    for e in rows {
        let row = Finding::denial(e).map(|f| super::egress::row_href(j, &f));
        entry(h, e, row.as_deref());
        h.raw("<div class=\"sub\">Decided by ")
            .node(&egress::layer_text(e.layer, &e.source))
            .raw(" · ");
        match egress::denial_check(e, &report.hub_rules) {
            Check::Nothing(why) => {
                h.text(why);
            }

            c => {
                h.raw("check ");
                check(h, &c, node);
            }
        }
        if at.propose
            && let Some(href) = super::egress::proposal_href(j, e)
        {
            h.raw(" · ");
            super::egress::proposal_link(
                h,
                &href,
                &Subject::of(j).label(j.project.as_deref(), &j.key_name, at.instances),
                None,
            );
        }
        h.raw("</div></li>");
    }
    h.raw("</ul>");
    omitted(h, tally);
    h.raw("</details>");
}

fn observed(h: &mut Html, report: &EgressReport, tally: &Tally) {
    if !tally.any() {
        return;
    }
    fold(h, 0, false);
    h.raw("Observed: ")
        .text(tally.destinations_text())
        .raw(" · ")
        .text(tally.attempts_text())
        .raw("</summary><p class=\"sub\">A DNS entry is a lookup, not proof of a connection.</p>")
        .raw("<ul class=\"access\">");
    for e in report
        .entries
        .iter()
        .filter(|e| e.outcome == EgressOutcome::Observed)
    {
        entry(h, e, None);
        h.raw("</li>");
    }
    h.raw("</ul>");
    omitted(h, tally);
    h.raw("</details>");
}

/// An entry's opening line, its `<li>` left open: the destination, linked to `row` when given,
/// protocol, phase and VM, how many attempts, when last seen, and the stage it was first seen in.
fn entry(h: &mut Html, e: &EgressEntry, row: Option<&str>) {
    h.raw("<li>");
    if let Some(row) = row {
        h.raw("<a href=\"").text(row).raw("\">");
    }
    h.raw("<code>")
        .node(&egress::destination_text(&e.destination))
        .raw("</code>");
    if row.is_some() {
        h.raw("</a>");
    }
    if !e.destination.allowable() {
        h.raw(" (not a name or an address)");
    }
    h.raw(" · ")
        .text(egress::protocol_text(e.protocol))
        .raw(" · ")
        .text(egress::phase_text(e.phase))
        .raw(" · ")
        .node(&egress::vm_text(&e.source))
        .raw(" · ")
        .text(Tally::attempts(e.count))
        .raw(", last ");
    pages::at(h, e.last_seen_ms / 1000);
    if let Some(stage) = &e.stage {
        h.raw(", first in <code>").node(stage).raw("</code>");
    }
}

fn omitted(h: &mut Html, tally: &Tally) {
    if tally.omitted > 0 {
        h.raw("<p class=\"sub\">")
            .text(tally.omitted)
            .raw(" more attempts not listed, past the report's bounds.</p>");
    }
}

/// Where to look, `[egress] allow_name` on node ci-1.
fn check(h: &mut Html, c: &Check, node: Option<&str>) {
    match c {
        Check::Node(key) => {
            h.raw("<code>").text(key).raw("</code> on ");
            match node {
                Some(name) => h.raw("node ").node(name),
                None => h.raw("its node"),
            };
        }
        Check::Variable { service, variable } => {
            if let Some(s) = service {
                h.raw("service ").node(s).raw("'s ");
            }
            h.raw("<code>")
                .text(variable)
                .raw("</code> in this job's CI configuration");
        }
        c @ Check::HubRules { .. } => {
            h.text(c.text());
        }
        Check::Nothing(why) => {
            h.text(why);
        }
    }
}

/// Each phase the job ran: how much of it the node recorded, and the bytes it forwarded.
fn coverage(h: &mut Html, report: &EgressReport) {
    h.raw("<table class=\"kv\"><tbody>");
    for p in &report.phases {
        let bytes = |n: Option<u64>, what: &str| match n {
            Some(n) => format!("{} {what}", pages::bytes(n)),
            None => format!("{what} not measured"),
        };
        pages::kv(
            h,
            egress::phase_text(p.phase),
            &format!(
                "{} · {}, {}",
                egress::coverage_text(p),
                bytes(p.sent_bytes, "sent"),
                bytes(p.received_bytes, "received")
            ),
        );
    }
    h.raw("</tbody></table><p class=\"sub\">");
    if report.phases.is_empty() {
        h.raw("No phase ran.");
    } else {
        h.raw("A phase not listed did not run.");
    }
    h.raw("</p>");
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::client::JobState;
    use vk_hub_proto::egress::{
        EgressCoverage, EgressDestination, EgressDimension, EgressLayer, EgressPhase,
        EgressPhaseReport, EgressProtocol, EgressRefusal, EgressSource, RefusalReason,
    };
    use vk_hub_proto::job::JobResult;

    use super::*;
    use crate::egress::testing::{entry, phase};

    fn shown(j: &JobRow, reports: bool) -> String {
        let mut h = Html::new();
        section(
            &mut h,
            j,
            Some("ci-1"),
            Shown {
                reports,
                propose: false,
                instances: Instances::None,
            },
        );
        h.into_string()
    }

    fn finished(egress: Option<EgressReport>) -> JobRow {
        let mut j = super::super::tests::history_job(1, "acme/web");
        j.node = Some("n1".into());
        j.started_at = Some(1_000);
        j.state = JobState::Finished;
        j.result = Some(JobResult {
            failure: None,
            exit_code: None,
            message: None,
            output_len: 0,
            artifacts: vec![],
            usage: None,
            events: vec![],
            egress,
        });
        j
    }

    /// Without a report the section says reporting is unavailable, never that nothing was
    /// reached; a job that never ran on a node has none.
    #[test]
    fn no_report_never_reads_as_no_traffic() {
        let mut j = super::super::tests::history_job(1, "acme/web");
        assert_eq!(shown(&j, true), "");
        j.node = Some("n1".into());
        j.state = JobState::Running;
        assert!(shown(&j, true).contains("Nothing reported yet"));
        // What its node sent so far, while it runs.
        j.egress = Some(EgressReport::default());
        let live = shown(&j, true);
        assert!(
            live.contains("None blocked") && live.contains("so far, while the job runs"),
            "{live}"
        );
        j.egress = None;
        let old = shown(&j, false);
        assert!(
            old.contains("Reporting unavailable") && old.contains("does not announce"),
            "{old}"
        );
        let ended = shown(&finished(None), true);
        assert!(
            ended.contains("Reporting unavailable")
                && ended.contains("This does not mean it made no network attempts"),
            "{ended}"
        );
    }

    /// A report shows its refusals as the failure's cause, its denials by deciding layer with
    /// where to look, its contacts folded, and each phase's coverage, guests' strings escaped.
    #[test]
    fn a_report_shows_each_outcome_and_where_to_look() {
        let report = EgressReport {
            revision: 1,
            entries: vec![
                entry(
                    EgressOutcome::Blocked,
                    EgressProtocol::Dns,
                    EgressDestination::domain("evil.example"),
                    Some(EgressLayer::NodeCap),
                ),
                entry(
                    EgressOutcome::Blocked,
                    EgressProtocol::Dns,
                    EgressDestination::domain("<b>x"),
                    Some(EgressLayer::Job),
                ),
                EgressEntry {
                    source: EgressSource::Service { name: "db".into() },
                    ..entry(
                        EgressOutcome::WouldBlock,
                        EgressProtocol::Tcp,
                        EgressDestination::address("10.0.0.1:443"),
                        Some(EgressLayer::Service),
                    )
                },
                entry(
                    EgressOutcome::Observed,
                    EgressProtocol::Dns,
                    EgressDestination::domain("crates.io"),
                    None,
                ),
            ],
            refusals: vec![
                EgressRefusal {
                    variable: "MICROVM_BUILD_EGRESS_ALLOW_NAME".into(),
                    entry: "pypi.org".into(),
                    dimension: EgressDimension::Name,
                    phase: EgressPhase::Build,
                    source: EgressSource::Job,
                    layer: Some(EgressLayer::NodeCap),
                    reason: RefusalReason::Unreachable,
                },
                EgressRefusal {
                    variable: "MICROVM_EGRESS_ALLOW_NAME".into(),
                    entry: "pypi.org/simple".into(),
                    dimension: EgressDimension::Name,
                    phase: EgressPhase::Run,
                    source: EgressSource::Job,
                    layer: None,
                    reason: RefusalReason::InvalidEntry,
                },
                EgressRefusal {
                    variable: "MICROVM_EGRESS_ALLOW_IP".into(),
                    entry: "192.0.2.0/24".into(),
                    dimension: EgressDimension::Ip,
                    phase: EgressPhase::Run,
                    source: EgressSource::Service { name: "db".into() },
                    layer: Some(EgressLayer::Job),
                    reason: RefusalReason::Unreachable,
                },
            ],
            refusals_omitted: 0,
            phases: vec![
                EgressPhaseReport {
                    sent_bytes: Some(2048),
                    ..phase(EgressPhase::Run, EgressCoverage::Complete)
                },
                phase(EgressPhase::Build, EgressCoverage::Unavailable),
            ],
            hub_rules: Vec::new(),
        };
        let html = shown(&finished(Some(report)), true);
        for want in [
            "<h2>Network access</h2>",
            "<span class=\"badge bad\">Declaration refused</span> \
             <a href=\"/egress?state=all&amp;project=key%3Ak\">On the Egress page</a>",
            "Declaration refused: 1, warnings: 2</summary>",
            "The job failed egress validation, before its script ran.",
            "A warning is an entry the job kept that a layer above leaves nothing of",
            "<code>MICROVM_BUILD_EGRESS_ALLOW_NAME</code> <code>pypi.org</code></a> · Build · \
             job: outside the node&#39;s cap: kept, but its lookups are refused",
            "<code>MICROVM_EGRESS_ALLOW_NAME</code> <code>pypi.org/simple</code></a> · Run · \
             job: not a valid DNS name suffix: the job failed",
            "Check <code>MICROVM_EGRESS_ALLOW_NAME</code> in this job's CI configuration.",
            "<code>MICROVM_EGRESS_ALLOW_IP</code> <code>192.0.2.0/24</code></a> · Run · \
             service db: outside this job&#39;s narrowing: kept, but reachable only as an \
             address of a name it allows",
            "Check service db's <code>MICROVM_EGRESS_ALLOW_IP</code> in this job's CI \
             configuration, or <code>MICROVM_EGRESS_ALLOW_IP</code> in this job's CI \
             configuration.",
            "Check <code>MICROVM_BUILD_EGRESS_ALLOW_NAME</code> in this job's CI \
             configuration, or <code>[egress.build] allow_name</code> on node ci-1.",
            "Blocked: 2 destinations · 2 attempts",
            "Their effect on the job's result is unknown.",
            "Decided by the node&#39;s cap · check <code>[egress] allow_name</code> on node ci-1",
            "<code>&lt;b&gt;x</code></a> (not a name or an address) · DNS · Run · job · 1 attempt",
            "narrowing · nothing to allow: not a name or an address</div>",
            "Would block: 1 destination · 1 attempt",
            "service db&#39;s narrowing · check service db's \
             <code>MICROVM_EGRESS_ALLOW_IP</code>",
            "<details class=\"fold\"><summary>Observed: 1 destination",
            "<li><code>crates.io</code> · DNS",
            "<th>Run</th><td>Complete: every recorded attempt is listed · 2.0 KiB sent, \
             received not measured</td>",
            "<th>Build</th><td>Unavailable: egress was not recorded",
        ] {
            assert!(html.contains(want), "{want}\n{html}");
        }
        assert!(!html.contains("<b>"), "{html}");
    }
}
