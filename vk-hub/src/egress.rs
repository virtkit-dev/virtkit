//! What the hub keeps of a placed job's egress report ([`EgressReport`], `docs/fleet-design.md`,
//! *Job egress from the hub*), and what it says in words: a node's report held to its bounds
//! again, the newest kept; counted per outcome; each denial's deciding layer and where to look
//! to change it, for a job's page, the job list and `vk-hub jobs show`.

use std::collections::HashSet;

use vk_hub_proto::client::JobState;
use vk_hub_proto::egress::{
    EgressCoverage, EgressDestination, EgressDimension, EgressEntry, EgressLayer, EgressOutcome,
    EgressPhase, EgressPhaseReport, EgressProtocol, EgressRefusal, EgressReport, EgressSource,
    RefusalReason,
};

use crate::store::JobRow;

pub mod rules;

/// The report to keep of `stored` and `incoming`: the one with the higher revision, `incoming`
/// on a tie, held to its bounds ([`EgressReport::bounded`]). A report is a cumulative snapshot,
/// so a replay replaces the counts rather than adding to them.
pub fn newest(
    stored: Option<EgressReport>,
    incoming: Option<EgressReport>,
) -> Option<EgressReport> {
    let incoming = incoming.map(EgressReport::bounded);
    match (stored, incoming) {
        (Some(s), Some(i)) if s.revision > i.revision => Some(s),
        (s, None) => s,
        (_, i) => i,
    }
}

/// How a job's egress stands, as far as the hub knows.
#[derive(Debug)]
pub enum Network<'a> {
    /// It never ran on a node: nothing to report.
    NotRun,
    /// It runs, and its node has sent no report yet.
    Pending,
    /// It ran, and no report came: from a node that sends none, or a result the hub made.
    Unavailable,
    /// Its node's report: of a job still running, what it recorded so far.
    Reported(&'a EgressReport),
}

/// Job `j`'s egress report: its result's once it has ended, the latest its node sent while it
/// runs.
pub fn report(j: &JobRow) -> Option<&EgressReport> {
    j.result
        .as_ref()
        .and_then(|r| r.egress.as_ref())
        .or(j.egress.as_ref())
}

/// How job `j`'s egress stands.
pub fn network(j: &JobRow) -> Network<'_> {
    if let Some(report) = report(j) {
        return Network::Reported(report);
    }
    match (j.state, j.started_at) {
        (JobState::Finished, Some(_)) => Network::Unavailable,
        (JobState::Finished, None) => Network::NotRun,
        _ if j.node.is_some() => Network::Pending,
        _ => Network::NotRun,
    }
}

/// The destinations of one outcome a report lists, and the attempts it recorded of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Distinct destinations listed, by protocol and destination: a port is kept, and the
    /// same destination in two phases or from two VMs counts once.
    pub destinations: usize,
    /// Attempts listed and not.
    pub attempts: u64,
    /// Attempts recorded but not listed, past the report's bounds: of destinations not
    /// counted above, for all the hub knows.
    pub omitted: u64,
}

impl Tally {
    pub fn any(&self) -> bool {
        self.destinations > 0 || self.omitted > 0
    }

    /// `1 destination`, `2 destinations`; `512+ destinations` when some were not listed.
    pub fn destinations_text(&self) -> String {
        let more = if self.omitted > 0 { "+" } else { "" };
        let n = if self.omitted > 0 {
            self.destinations.max(1)
        } else {
            self.destinations
        };
        let plural = if n == 1 && more.is_empty() { "" } else { "s" };
        format!("{n}{more} destination{plural}")
    }

    /// `1 attempt`, `5 attempts`.
    pub fn attempts_text(&self) -> String {
        Tally::attempts(self.attempts)
    }

    /// `n` attempts in words: `1 attempt`, `5 attempts`.
    pub fn attempts(n: u64) -> String {
        let plural = if n == 1 { "" } else { "s" };
        format!("{n} attempt{plural}")
    }
}

/// What a report says, counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub blocked: Tally,
    pub would_block: Tally,
    pub observed: Tally,
    /// Declarations that failed the job, listed and not: an invalid entry, or a reason this hub
    /// does not know.
    pub refusals: u64,
    /// Declarations kept that a layer above leaves nothing of ([`RefusalReason::Unreachable`]),
    /// listed and not: the job ran with them.
    pub unreachable: u64,
    /// Whether every phase the job ran recorded everything: no phase partial or unavailable.
    pub complete: bool,
}

impl Summary {
    pub fn of(r: &EgressReport) -> Self {
        let failed = r
            .refusals
            .iter()
            .filter(|f| f.reason.fails_job() != Some(false))
            .count() as u64;
        let kept = r.refusals.len() as u64 - failed;
        // A report lists those that failed the job first, so those it leaves out are warnings
        // unless every one listed failed it.
        let (refusals, unreachable) = match (failed, kept) {
            (n, 0) if n > 0 => (n.saturating_add(r.refusals_omitted), 0),
            (n, kept) => (n, kept.saturating_add(r.refusals_omitted)),
        };
        let mut s = Summary {
            refusals,
            unreachable,
            complete: r
                .phases
                .iter()
                .all(|p| p.coverage == EgressCoverage::Complete),
            ..Summary::default()
        };
        let mut seen: [HashSet<(EgressProtocol, &EgressDestination)>; 3] = Default::default();
        for e in &r.entries {
            let at = outcome_index(e.outcome);
            if let (Some(seen), Some(t)) = (seen.get_mut(at), s.tallies_mut().get_mut(at)) {
                if seen.insert((e.protocol, &e.destination)) {
                    t.destinations += 1;
                }
                t.attempts = t.attempts.saturating_add(e.count);
            }
        }
        for p in &r.phases {
            let o = p.omitted;
            for (t, n) in s
                .tallies_mut()
                .into_iter()
                .zip([o.blocked, o.would_block, o.observed])
            {
                t.omitted = t.omitted.saturating_add(n);
                t.attempts = t.attempts.saturating_add(n);
            }
        }
        s
    }

    fn tallies_mut(&mut self) -> [&mut Tally; 3] {
        [&mut self.blocked, &mut self.would_block, &mut self.observed]
    }

    /// Everything counted, on a line: `Declaration refused (1) · Declaration warnings (1) ·
    /// Blocked: 2 destinations (5 attempts) · Observed: 4 destinations (9 attempts) · incomplete
    /// record`.
    pub fn text(&self) -> String {
        let mut parts = Vec::new();
        if self.refusals > 0 {
            parts.push(format!("Declaration refused ({})", self.refusals));
        }
        if self.unreachable > 0 {
            parts.push(format!("Declaration warnings ({})", self.unreachable));
        }
        let tallies = [("Blocked", self.blocked), ("Would block", self.would_block)];
        if self.refusals == 0 && !tallies.iter().any(|(_, t)| t.any()) {
            // Nothing blocked only as far as the node recorded.
            parts.push(match self.complete {
                true => "None blocked".to_string(),
                false => "No blocks recorded".to_string(),
            });
        }
        for (label, t) in tallies.into_iter().chain([("Observed", self.observed)]) {
            if t.any() {
                parts.push(format!(
                    "{label}: {} ({})",
                    t.destinations_text(),
                    t.attempts_text()
                ));
            }
        }
        if !self.complete {
            parts.push("incomplete record".to_string());
        }
        parts.join(" · ")
    }
}

/// Which of [`Summary`]'s tallies an outcome counts in. An outcome from a later peer counts
/// as blocked, as the report's omissions count it.
fn outcome_index(o: EgressOutcome) -> usize {
    match o {
        EgressOutcome::Blocked | EgressOutcome::Other => 0,
        EgressOutcome::WouldBlock => 1,
        EgressOutcome::Observed => 2,
    }
}

/// A destination as a page shows it: `crates.io`, `10.0.0.1:443`, or the text a guest sent.
pub fn destination_text(d: &EgressDestination) -> String {
    match d {
        EgressDestination::Domain { name } => name.clone(),
        EgressDestination::Address { ip, port } => format!("{ip}:{port}"),
        EgressDestination::Malformed { text } => text.clone(),
        EgressDestination::Other => "a destination of a kind this hub does not know".to_string(),
    }
}

pub fn protocol_text(p: EgressProtocol) -> &'static str {
    match p {
        EgressProtocol::Dns => "DNS",
        EgressProtocol::Tcp => "TCP",
        EgressProtocol::Udp => "UDP",
        EgressProtocol::Other => "other protocol",
    }
}

pub fn phase_text(p: EgressPhase) -> &'static str {
    match p {
        EgressPhase::Run => "Run",
        EgressPhase::Build => "Build",
        EgressPhase::Other => "Other phase",
    }
}

/// The VM a flow came from: `job`, `service db`.
pub fn vm_text(s: &EgressSource) -> String {
    match s {
        EgressSource::Job => "job".to_string(),
        EgressSource::Service { name } => format!("service {name}"),
        EgressSource::Other => "another VM".to_string(),
    }
}

/// The layer that decided a denial of a flow from `source`.
pub fn layer_text(layer: Option<EgressLayer>, source: &EgressSource) -> String {
    match (layer, source) {
        (Some(EgressLayer::NodeCap), _) => "the node's cap".to_string(),
        (Some(EgressLayer::HubRule), _) => "a hub rule".to_string(),
        (Some(EgressLayer::Job), _) => "this job's narrowing".to_string(),
        (Some(EgressLayer::Service), EgressSource::Service { name }) => {
            format!("service {name}'s narrowing")
        }
        (Some(EgressLayer::Service), _) => "a service's narrowing".to_string(),
        (Some(EgressLayer::Unknown) | None, _) => "an unknown layer".to_string(),
    }
}

/// Where to look to change what a layer allows. Changing it may not be enough: another layer
/// may still block the destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    /// A key of the node's config, `[egress.build] allow_name`.
    Node(&'static str),
    /// A variable of the job's CI configuration, the named service's when it has one.
    Variable {
        service: Option<String>,
        variable: &'static str,
    },
    /// The hub's egress rules that decided it, by name: those the job ran under, or the one
    /// dry-run rule that would have refused it.
    HubRules { rules: Vec<String>, dry_run: bool },
    /// Nothing to change, and why.
    Nothing(&'static str),
}

impl Check {
    /// In words, for a terminal: `[egress] allow_name on its node`.
    pub fn text(&self) -> String {
        match self {
            Check::Node(key) => format!("{key} on its node"),
            Check::Variable {
                service: None,
                variable,
            } => format!("{variable} in this job's CI configuration"),
            Check::Variable {
                service: Some(s),
                variable,
            } => format!("service {s}'s {variable} in this job's CI configuration"),
            Check::HubRules { rules, dry_run } => hub_rules_text(rules, *dry_run),
            Check::Nothing(why) => why.to_string(),
        }
    }
}

/// The hub's egress rules `rules` in words: `the hub's egress rules wab, wab-branches`, the
/// Fallback named as such.
fn hub_rules_text(rules: &[String], dry_run: bool) -> String {
    let names: Vec<String> = rules
        .iter()
        .map(|r| match r.as_str() {
            crate::store::DEFAULT_RULE => "the Fallback (default)".to_string(),
            r => r.to_string(),
        })
        .collect();
    match (names.as_slice(), dry_run) {
        ([], _) => {
            "the hub's egress rules: none selects the job, and no Fallback is enforced".to_string()
        }
        ([one], true) => format!("the hub's dry-run egress rule {one}"),
        ([one], false) => format!("the hub's egress rule {one}"),
        (_, _) => format!("the hub's egress rules {}", names.join(", ")),
    }
}

/// The dimension an allow entry for `d` would be in, if any could be written.
fn dimension(d: &EgressDestination) -> Option<EgressDimension> {
    match d {
        EgressDestination::Domain { .. } => Some(EgressDimension::Name),
        EgressDestination::Address { .. } => Some(EgressDimension::Ip),
        _ => None,
    }
}

/// The node's config key for `dimension` in `phase`.
fn node_key(phase: EgressPhase, dimension: EgressDimension) -> Option<&'static str> {
    Some(match (phase, dimension) {
        (EgressPhase::Run, EgressDimension::Name) => "[egress] allow_name",
        (EgressPhase::Run, EgressDimension::Ip) => "[egress] allow_ip",
        (EgressPhase::Build, EgressDimension::Name) => "[egress.build] allow_name",
        (EgressPhase::Build, EgressDimension::Ip) => "[egress.build] allow_ip",
        _ => return None,
    })
}

/// The job's or a service's variable for `dimension` in `phase`.
fn variable(phase: EgressPhase, dimension: EgressDimension) -> Option<&'static str> {
    Some(match (phase, dimension) {
        (EgressPhase::Run, EgressDimension::Name) => "MICROVM_EGRESS_ALLOW_NAME",
        (EgressPhase::Run, EgressDimension::Ip) => "MICROVM_EGRESS_ALLOW_IP",
        (EgressPhase::Build, EgressDimension::Name) => "MICROVM_BUILD_EGRESS_ALLOW_NAME",
        (EgressPhase::Build, EgressDimension::Ip) => "MICROVM_BUILD_EGRESS_ALLOW_IP",
        _ => return None,
    })
}

/// Where to look to allow denial `e`, by the layer that decided it; `hub_rules` are those the
/// job ran under ([`EgressReport::hub_rules`]), which decided it if a hub rule did and it was
/// not a dry-run rule's.
pub fn denial_check(e: &EgressEntry, hub_rules: &[String]) -> Check {
    let Some(dim) = dimension(&e.destination) else {
        return Check::Nothing("nothing to allow: not a name or an address");
    };
    let service = match &e.source {
        EgressSource::Service { name } => Some(name.clone()),
        _ => None,
    };
    match e.layer {
        Some(EgressLayer::NodeCap) => node_key(e.phase, dim).map(Check::Node),
        Some(EgressLayer::Job) => variable(e.phase, dim).map(|variable| Check::Variable {
            service: None,
            variable,
        }),
        Some(EgressLayer::Service) if service.is_some() => {
            variable(e.phase, dim).map(|variable| Check::Variable { service, variable })
        }
        Some(EgressLayer::HubRule) => Some(match &e.rule {
            Some(rule) if e.outcome == EgressOutcome::WouldBlock => Check::HubRules {
                rules: vec![rule.clone()],
                dry_run: true,
            },
            _ => Check::HubRules {
                rules: hub_rules.to_vec(),
                dry_run: false,
            },
        }),
        _ => None,
    }
    .unwrap_or(Check::Nothing(
        "no setting to point at: the layer is unknown",
    ))
}

/// What is wrong with declaration `r`, and whether its job failed for it.
pub fn refusal_reason_text(r: &EgressRefusal) -> String {
    // A refusal names the layer it falls outside, never a narrowing below the job's.
    let outside = match r.layer {
        Some(EgressLayer::HubRule) => "the hub's rules".to_string(),
        layer => layer_text(layer, &r.source),
    };
    match (r.reason, r.dimension) {
        (RefusalReason::Unreachable, EgressDimension::Ip) => {
            format!("outside {outside}: kept, but reachable only as an address of a name it allows")
        }
        (RefusalReason::Unreachable, _) => {
            format!("outside {outside}: kept, but its lookups are refused")
        }
        (RefusalReason::InvalidEntry, EgressDimension::Name) => {
            "not a valid DNS name suffix: the job failed".to_string()
        }
        (RefusalReason::InvalidEntry, EgressDimension::Ip) => {
            "not a valid IPv4 range: the job failed".to_string()
        }
        _ => "refused, for a reason this hub does not know".to_string(),
    }
}

/// Where to look to fix refusal `r`: the declaration first, then, for one outside the node's
/// cap or the job's narrowing, that.
pub fn refusal_checks(r: &EgressRefusal) -> Vec<Check> {
    let service = match &r.source {
        EgressSource::Service { name } => Some(name.clone()),
        _ => None,
    };
    let service_entry = service.is_some();
    let mut checks = Vec::new();
    // The variable as the node named it, when it is one of the four.
    if let Some(variable) = variable(r.phase, r.dimension).filter(|v| *v == r.variable) {
        checks.push(Check::Variable { service, variable });
    }
    let outside = r.reason == RefusalReason::Unreachable;
    match r.layer {
        Some(EgressLayer::NodeCap) if outside => {
            checks.extend(node_key(r.phase, r.dimension).map(Check::Node));
        }
        // A service's entry outside the job's own narrowing.
        Some(EgressLayer::Job) if outside && service_entry => {
            checks.extend(
                variable(r.phase, r.dimension).map(|variable| Check::Variable {
                    service: None,
                    variable,
                }),
            );
        }
        _ => {}
    }
    checks
}

/// How much of phase `p` the node recorded: `Complete`, `Partial: 12 blocked attempts not
/// listed`, `Unavailable: egress was not recorded`.
pub fn coverage_text(p: &EgressPhaseReport) -> String {
    match p.coverage {
        EgressCoverage::Complete => "Complete: every recorded attempt is listed".to_string(),
        EgressCoverage::Partial => {
            let o = p.omitted;
            let counts: Vec<String> = [
                (o.blocked, "blocked"),
                (o.would_block, "would-block"),
                (o.observed, "observed"),
            ]
            .into_iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, what)| format!("{n} {what}"))
            .collect();
            if counts.is_empty() {
                "Partial: recording incomplete".to_string()
            } else {
                format!(
                    "Partial: recording incomplete, {} attempts not listed",
                    counts.join(", ")
                )
            }
        }
        EgressCoverage::Unavailable => "Unavailable: egress was not recorded".to_string(),
        EgressCoverage::Other => "Unknown: reported in a form this hub does not know".to_string(),
    }
}

/// The hub's egress rules a job was placed under, in words: `wab, wab-branches; dry-run
/// wab-release (rules generation 7)`.
pub fn rules_applied_text(a: &crate::store::EgressRulesApplied) -> String {
    let named = |rules: &[String]| {
        rules
            .iter()
            .map(|r| match r.as_str() {
                crate::store::DEFAULT_RULE => "the Fallback (default)".to_string(),
                r => r.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = match a.rules.as_slice() {
        [] => "none: no rule selects it and no Fallback is enforced, so it may reach nothing"
            .to_string(),
        rules => named(rules),
    };
    if !a.dry_run.is_empty() {
        out.push_str(&format!("; dry-run {}", named(&a.dry_run)));
    }
    out.push_str(&format!(" (rules generation {})", a.generation));
    out
}

/// The most entries of each kind [`lines`] lists.
const LINES_PER_KIND: usize = 10;

/// Job `j`'s egress for a terminal, a `(key, value)` a line: the summary, then at most
/// [`LINES_PER_KIND`] refusals, blocked and would-block destinations, then each phase's
/// coverage. Nothing for a job that never ran on a node. The values hold a guest's strings:
/// the caller makes them display-safe.
pub fn lines(j: &JobRow) -> Vec<(&'static str, String)> {
    let report = match network(j) {
        Network::NotRun => return Vec::new(),
        Network::Pending => {
            return vec![("network", "nothing reported yet".to_string())];
        }
        Network::Unavailable => {
            return vec![(
                "network",
                "reporting unavailable: its node sent no egress report".to_string(),
            )];
        }
        Network::Reported(report) => report,
    };
    let mut summary = Summary::of(report).text();
    if j.state != JobState::Finished {
        summary.push_str(" · so far, while the job runs");
    }
    let mut out = vec![("network", summary)];
    let more = |out: &mut Vec<(&'static str, String)>, total: usize| {
        if let Some(n) = total.checked_sub(LINES_PER_KIND).filter(|n| *n > 0) {
            out.push(("", format!("… {n} more on the job's page")));
        }
    };
    for r in report.refusals.iter().take(LINES_PER_KIND) {
        let checks: Vec<String> = refusal_checks(r).iter().map(Check::text).collect();
        let check = match checks.is_empty() {
            true => "correct it in this job's CI configuration".to_string(),
            false => format!("check {}", checks.join(", or ")),
        };
        out.push((
            match r.reason.fails_job() {
                Some(false) => "warning",
                _ => "refused",
            },
            format!(
                "{} {} ({}, {}): {}; {check}",
                r.variable,
                r.entry,
                phase_text(r.phase).to_lowercase(),
                vm_text(&r.source),
                refusal_reason_text(r),
            ),
        ));
    }
    more(&mut out, report.refusals.len());
    for (key, blocked) in [("blocked", true), ("would block", false)] {
        let denials: Vec<&EgressEntry> = report
            .entries
            .iter()
            .filter(|e| {
                e.outcome.is_denial() && (e.outcome == EgressOutcome::WouldBlock) != blocked
            })
            .collect();
        for e in denials.iter().take(LINES_PER_KIND) {
            let check = match denial_check(e, &report.hub_rules) {
                Check::Nothing(why) => why.to_string(),
                c => format!("check {}", c.text()),
            };
            out.push((
                key,
                format!(
                    "{} {} ({}, {}, {}): {}; {check}",
                    protocol_text(e.protocol),
                    destination_text(&e.destination),
                    phase_text(e.phase).to_lowercase(),
                    vm_text(&e.source),
                    Tally::attempts(e.count),
                    layer_text(e.layer, &e.source),
                ),
            ));
        }
        more(&mut out, denials.len());
    }
    for p in &report.phases {
        let bytes = |n: Option<u64>, what: &str| match n {
            Some(n) => format!("{n} bytes {what}"),
            None => format!("{what} not measured"),
        };
        out.push((
            "coverage",
            format!(
                "{}: {}; {}, {}",
                phase_text(p.phase).to_lowercase(),
                coverage_text(p),
                bytes(p.sent_bytes, "sent"),
                bytes(p.received_bytes, "received"),
            ),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(revision: u64) -> EgressReport {
        EgressReport {
            revision,
            ..EgressReport::default()
        }
    }

    use super::testing::{entry, phase};
    use vk_hub_proto::egress::EgressOmitted;

    fn domain(name: &str) -> EgressDestination {
        EgressDestination::Domain { name: name.into() }
    }

    /// Destinations count by protocol and destination, once across phases and VMs; what was
    /// not listed counts as attempts, and makes the count a lower bound.
    #[test]
    fn a_report_is_counted_by_outcome_and_destination() {
        use EgressOutcome::*;
        let job = Some(EgressLayer::Job);
        let mut r = EgressReport {
            entries: vec![
                entry(Blocked, EgressProtocol::Dns, domain("a.example"), job),
                EgressEntry {
                    phase: EgressPhase::Build,
                    source: EgressSource::Service { name: "db".into() },
                    count: 4,
                    ..entry(Blocked, EgressProtocol::Dns, domain("a.example"), job)
                },
                entry(Blocked, EgressProtocol::Tcp, domain("a.example"), job),
                entry(Other, EgressProtocol::Other, EgressDestination::Other, None),
                entry(Observed, EgressProtocol::Dns, domain("b.example"), None),
            ],
            phases: vec![phase(EgressPhase::Run, EgressCoverage::Complete)],
            ..EgressReport::default()
        };
        let s = Summary::of(&r);
        assert_eq!(
            s.blocked,
            Tally {
                destinations: 3,
                attempts: 7,
                omitted: 0
            }
        );
        assert_eq!(
            (s.would_block, s.refusals, s.complete),
            (Tally::default(), 0, true)
        );
        assert_eq!(s.observed.destinations_text(), "1 destination");

        r.entries.clear();
        r.phases[0].coverage = EgressCoverage::Partial;
        r.phases[0].omitted = EgressOmitted {
            would_block: 3,
            ..EgressOmitted::default()
        };
        let s = Summary::of(&r);
        assert_eq!((s.would_block.attempts, s.would_block.omitted), (3, 3));
        // A declaration kept unreachable warns below what was carried; one that failed the job
        // comes first. Those not listed are warnings, a report listing failures first, unless
        // every one listed failed the job.
        let refusal = |reason| EgressRefusal {
            variable: "MICROVM_EGRESS_ALLOW_NAME".into(),
            entry: "pypi.org".into(),
            dimension: EgressDimension::Name,
            phase: EgressPhase::Run,
            source: EgressSource::Job,
            layer: Some(EgressLayer::NodeCap),
            reason,
        };
        r.refusals = vec![refusal(RefusalReason::Unreachable)];
        r.refusals_omitted = 1;
        let s = Summary::of(&r);
        assert_eq!((s.refusals, s.unreachable), (0, 2));
        r.phases[0].omitted = EgressOmitted::default();
        r.phases[0].coverage = EgressCoverage::Complete;
        r.refusals.push(refusal(RefusalReason::InvalidEntry));
        let s = Summary::of(&r);
        assert_eq!((s.refusals, s.unreachable), (1, 2));
        assert_eq!(
            s.text(),
            "Declaration refused (1) · Declaration warnings (2)"
        );
        r.refusals.remove(0);
        let s = Summary::of(&r);
        assert_eq!((s.refusals, s.unreachable), (2, 0));
    }

    /// A denial points at the setting of the layer that decided it, in its phase and dimension;
    /// one that names no destination, or whose layer is unknown, at none.
    #[test]
    fn a_denial_points_at_the_layer_that_decided_it() {
        let check = |phase, source, layer, destination| {
            denial_check(
                &EgressEntry {
                    phase,
                    source,
                    ..entry(
                        EgressOutcome::Blocked,
                        EgressProtocol::Tcp,
                        destination,
                        layer,
                    )
                },
                &[],
            )
        };
        let addr = EgressDestination::address("10.0.0.1:443");
        let db = EgressSource::Service { name: "db".into() };
        let (run, build, job) = (EgressPhase::Run, EgressPhase::Build, EgressSource::Job);
        let cap = Some(EgressLayer::NodeCap);
        assert_eq!(
            check(run, job.clone(), cap, domain("a.example")),
            Check::Node("[egress] allow_name")
        );
        assert_eq!(
            check(build, job.clone(), cap, addr.clone()),
            Check::Node("[egress.build] allow_ip")
        );
        assert_eq!(
            check(
                build,
                job.clone(),
                Some(EgressLayer::Job),
                domain("a.example")
            ),
            Check::Variable {
                service: None,
                variable: "MICROVM_BUILD_EGRESS_ALLOW_NAME"
            }
        );
        assert_eq!(
            check(run, db.clone(), Some(EgressLayer::Service), addr.clone()),
            Check::Variable {
                service: Some("db".into()),
                variable: "MICROVM_EGRESS_ALLOW_IP"
            }
        );
        assert!(matches!(
            check(run, db, Some(EgressLayer::Unknown), addr),
            Check::Nothing(_)
        ));
        assert!(matches!(
            check(
                run,
                job.clone(),
                cap,
                EgressDestination::domain("not a name")
            ),
            Check::Nothing(_)
        ));
        // A hub rule's, by name: those the job ran under, or the dry-run rule's own.
        let hub = |outcome, rule: Option<&str>, rules: &[String]| {
            denial_check(
                &EgressEntry {
                    rule: rule.map(str::to_string),
                    ..entry(
                        outcome,
                        EgressProtocol::Dns,
                        domain("a.example"),
                        Some(EgressLayer::HubRule),
                    )
                },
                rules,
            )
            .text()
        };
        let ran = ["wab".to_string(), "default".to_string()];
        assert_eq!(
            hub(EgressOutcome::Blocked, None, &ran),
            "the hub's egress rules wab, the Fallback (default)"
        );
        assert_eq!(
            hub(EgressOutcome::WouldBlock, Some("wab-release"), &ran),
            "the hub's dry-run egress rule wab-release"
        );
        assert_eq!(
            hub(EgressOutcome::Blocked, None, &["default".to_string()]),
            "the hub's egress rule the Fallback (default)"
        );
        assert!(hub(EgressOutcome::Blocked, None, &[]).contains("none selects the job"));
    }

    /// A refusal points at its declaration, and when wider than the node's cap at the cap too;
    /// partial coverage says what it left out when it knows.
    #[test]
    fn a_refusal_points_at_its_declaration_and_the_cap() {
        let refusal = EgressRefusal {
            variable: "MICROVM_EGRESS_ALLOW_NAME".into(),
            entry: "evil.com".into(),
            dimension: EgressDimension::Name,
            phase: EgressPhase::Run,
            source: EgressSource::Service { name: "db".into() },
            layer: Some(EgressLayer::NodeCap),
            reason: RefusalReason::Unreachable,
        };
        assert_eq!(
            refusal_checks(&refusal),
            [
                Check::Variable {
                    service: Some("db".into()),
                    variable: "MICROVM_EGRESS_ALLOW_NAME"
                },
                Check::Node("[egress] allow_name")
            ]
        );
        // Kept: a name's lookups are refused, an address passes only as a name's.
        let kept = refusal.clone();
        assert_eq!(
            refusal_reason_text(&kept),
            "outside the node's cap: kept, but its lookups are refused"
        );
        let address = EgressRefusal {
            dimension: EgressDimension::Ip,
            variable: "MICROVM_EGRESS_ALLOW_IP".into(),
            layer: Some(EgressLayer::HubRule),
            ..kept.clone()
        };
        assert_eq!(
            refusal_reason_text(&address),
            "outside the hub's rules: kept, but reachable only as an address of a name it allows"
        );
        // A service's entry outside the job's narrowing points at the job's variable too.
        let below_job = EgressRefusal {
            layer: Some(EgressLayer::Job),
            ..kept
        };
        assert_eq!(
            refusal_checks(&below_job),
            [
                Check::Variable {
                    service: Some("db".into()),
                    variable: "MICROVM_EGRESS_ALLOW_NAME"
                },
                Check::Variable {
                    service: None,
                    variable: "MICROVM_EGRESS_ALLOW_NAME"
                },
            ]
        );
        assert_eq!(
            refusal_reason_text(&below_job),
            "outside this job's narrowing: kept, but its lookups are refused"
        );
        let invalid = EgressRefusal {
            dimension: EgressDimension::Ip,
            variable: "SOMETHING_ELSE".into(),
            layer: None,
            reason: RefusalReason::InvalidEntry,
            ..refusal
        };
        assert_eq!(refusal_checks(&invalid), []);
        assert_eq!(
            refusal_reason_text(&invalid),
            "not a valid IPv4 range: the job failed"
        );

        let mut p = phase(EgressPhase::Build, EgressCoverage::Partial);
        assert_eq!(coverage_text(&p), "Partial: recording incomplete");
        p.omitted.blocked = 12;
        p.omitted.observed = 3;
        assert_eq!(
            coverage_text(&p),
            "Partial: recording incomplete, 12 blocked, 3 observed attempts not listed"
        );
    }

    #[test]
    fn the_newest_report_is_kept() {
        let rev = |r: Option<EgressReport>| r.map(|r| r.revision);
        assert_eq!(rev(newest(Some(report(2)), Some(report(1)))), Some(2));
        assert_eq!(rev(newest(Some(report(1)), Some(report(2)))), Some(2));
        assert_eq!(rev(newest(None, Some(report(1)))), Some(1));
        assert_eq!(rev(newest(Some(report(1)), None)), Some(1));
        assert_eq!(rev(newest(None, None)), None);
        // A tie takes the incoming one, held to the bounds.
        let mut incoming = report(3);
        incoming.refusals_omitted = 7;
        incoming.refusals = vec![
            vk_hub_proto::egress::EgressRefusal {
                variable: "MICROVM_EGRESS_ALLOW_NAME\x1b[2J".into(),
                entry: "evil.com".into(),
                dimension: vk_hub_proto::egress::EgressDimension::Name,
                phase: vk_hub_proto::egress::EgressPhase::Run,
                source: vk_hub_proto::egress::EgressSource::Job,
                layer: None,
                reason: vk_hub_proto::egress::RefusalReason::InvalidEntry,
            };
            vk_hub_proto::egress::MAX_EGRESS_REFUSALS + 1
        ];
        let kept = newest(Some(report(3)), Some(incoming)).unwrap();
        assert_eq!(
            kept.refusals.len(),
            vk_hub_proto::egress::MAX_EGRESS_REFUSALS
        );
        assert_eq!(kept.refusals_omitted, 8);
        assert!(!kept.refusals[0].variable.contains('\x1b'));
    }
}

/// Reports for tests.
#[cfg(test)]
pub(crate) mod testing {
    use vk_hub_proto::egress::{
        EgressCoverage, EgressDestination, EgressEntry, EgressLayer, EgressOmitted, EgressOutcome,
        EgressPhase, EgressPhaseReport, EgressProtocol, EgressSource,
    };

    /// One attempt from the job's VM in the run phase, decided by `layer` for a denial.
    pub fn entry(
        outcome: EgressOutcome,
        protocol: EgressProtocol,
        destination: EgressDestination,
        layer: Option<EgressLayer>,
    ) -> EgressEntry {
        EgressEntry {
            outcome,
            protocol,
            destination,
            phase: EgressPhase::Run,
            source: EgressSource::Job,
            layer,
            count: 1,
            first_seen_ms: 1_000_000,
            last_seen_ms: 1_000_000,
            stage: None,
            rule: None,
        }
    }

    pub fn phase(phase: EgressPhase, coverage: EgressCoverage) -> EgressPhaseReport {
        EgressPhaseReport {
            phase,
            coverage,
            omitted: EgressOmitted::default(),
            sent_bytes: None,
            received_bytes: None,
            caps: None,
        }
    }
}
