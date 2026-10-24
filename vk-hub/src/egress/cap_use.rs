//! Which entries of the nodes' own egress caps the hub's jobs use (`docs/fleet-design.md`,
//! *Observed traffic*), as [`super::rule_use`] tells it of the rules' entries: a contact counts
//! toward every entry of its node's cap that allows it, for the jobs on the node that ran the
//! phase held to its caps as they are now: the same fingerprint, as the phase's report names it
//! ([`vk_hub_proto::egress::EgressPhaseReport::caps`]), or for an older node's job as it was
//! placed under ([`crate::store::JobRow::egress_caps`]). A node reads its config once, its
//! executors as they start: a job may be held to caps its node's inventory does not say yet. An
//! entry no contact matched within [`USE_DAYS`] has *no observed use*, beside the coverage that
//! qualifies it. Only placed jobs report: other workloads on the node, its gitlab-runner's jobs
//! among them, may use an entry the hub never sees used. Nothing is removed.
//!
//! The scan is bounded: the latest [`SCAN`] jobs of the history, and it says when it was cut.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use vk_hub_proto::egress::{EgressCaps, EgressCoverage, EgressOutcome, HubPhase, NodeEgressCaps};

use super::matching::{Dest, Verdict, verdict};
use super::rule_use::{Coverage, EntryUse, PHASES, USE_DAYS};
use crate::store::{JobRow, NodeRow};

/// The latest jobs of the history read.
pub const SCAN: usize = 10_000;

/// The caps' use, by node ID and phase.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapUse {
    /// Each entry's, by `(node, phase, entry)`: every listed entry has one.
    pub entries: BTreeMap<(String, &'static str, String), EntryUse>,
    pub coverage: BTreeMap<(String, &'static str), Coverage>,
    /// Per node, the jobs placed under its caps now that sent no report, within [`USE_DAYS`]:
    /// which phases they ran is unknown.
    pub unreported: BTreeMap<String, u64>,
    /// Per node, the first day a job placed under its caps now ended on, within [`USE_DAYS`]:
    /// a later day than the window's first says the caps are younger than it.
    pub since_day: BTreeMap<String, u64>,
    /// Whether the scan was cut before the window's start.
    pub capped: bool,
}

/// How an entry stands, as a rule entry's does ([`super::rule_use::Standing`]).
pub use super::rule_use::Standing;

impl CapUse {
    /// How entry `entry` of `node`'s `phase` cap stands.
    pub fn standing(&self, node: &str, phase: &'static str, entry: &str) -> Standing {
        let used = self
            .entries
            .get(&(node.to_string(), phase, entry.to_string()))
            .is_some_and(|u| u.jobs > 0);
        let reported = self
            .coverage
            .get(&(node.to_string(), phase))
            .is_some_and(|c| c.complete > 0);
        match (used, reported && !self.capped) {
            (true, _) => Standing::Used,
            (false, true) => Standing::Unused,
            (false, false) => Standing::NoEvidence,
        }
    }

    /// The entries of `node`'s caps with no observed use, as `(phase, entry)`.
    pub fn unused(&self, node: &str) -> Vec<(&'static str, &str)> {
        self.entries
            .keys()
            .filter(|(n, _, _)| n == node)
            .filter(|(n, p, e)| self.standing(n, p, e) == Standing::Unused)
            .map(|(_, p, e)| (*p, e.as_str()))
            .collect()
    }
}

/// The caps `n` reports, when it lists them.
pub fn listed(n: &NodeRow) -> Option<&EgressCaps> {
    match n.inventory.as_ref()?.egress_caps.as_ref()? {
        NodeEgressCaps::Listed(c) => Some(c),
        _ => None,
    }
}

/// `caps`' phase `key`.
pub fn phase_of<'a>(caps: &'a EgressCaps, key: &str) -> Option<&'a HubPhase> {
    match key {
        "run" => Some(&caps.run),
        "build" => Some(&caps.build),
        _ => None,
    }
}

/// The use of nodes' caps' entries, as the latest [`SCAN`] jobs of the history are visited,
/// newest first, one at a time: nothing of a job is kept but what it counts.
pub struct Scan<'a> {
    caps: HashMap<&'a str, &'a EgressCaps>,
    since: u64,
    read: usize,
    last_day: Option<u64>,
    out: CapUse,
}

/// Note that a job of `node` under its caps now counts on `day`.
fn since(out: &mut CapUse, node: &str, day: u64) {
    let first = out.since_day.entry(node.to_string()).or_insert(day);
    *first = (*first).min(day);
}

/// The day job `j` counts on: its end, else its start, else its submission.
fn day_of(j: &JobRow) -> u64 {
    j.finished_at.or(j.started_at).unwrap_or(j.created_at) / 86_400
}

impl<'a> Scan<'a> {
    pub fn new(nodes: &'a [(String, NodeRow)], today: u64) -> Self {
        let mut out = CapUse::default();
        let caps: HashMap<&str, &EgressCaps> = nodes
            .iter()
            .filter_map(|(id, n)| Some((id.as_str(), listed(n)?)))
            .collect();
        for (id, c) in &caps {
            for key in PHASES {
                if let Some(HubPhase::Allow { names, ips }) = phase_of(c, key) {
                    for e in names.iter().chain(ips) {
                        out.entries
                            .insert((id.to_string(), key, e.clone()), EntryUse::default());
                    }
                }
            }
        }
        Scan {
            caps,
            since: today.saturating_sub(USE_DAYS - 1),
            read: 0,
            last_day: None,
            out,
        }
    }

    /// Whether any job can count: some node lists its caps.
    pub fn reads_jobs(&self) -> bool {
        !self.caps.is_empty()
    }

    /// Count job `j`, the next newest-first.
    pub fn visit(&mut self, j: &JobRow) {
        let out = &mut self.out;
        let day = day_of(j);
        self.read = self.read.saturating_add(1);
        self.last_day = Some(day);
        if day < self.since {
            return;
        }
        let Some((node, c)) = (j.node.as_deref()).and_then(|n| Some((n, *self.caps.get(n)?)))
        else {
            return;
        };
        let placed = j.egress_caps.as_deref() == Some(c.fingerprint.as_str());
        let Some(report) = super::report(j) else {
            // Only a job that ran sends one.
            if placed {
                since(out, node, day);
                if j.started_at.is_some() {
                    let n = out.unreported.entry(node.to_string()).or_default();
                    *n = n.saturating_add(1);
                }
            }
            return;
        };
        if placed {
            since(out, node, day);
        }
        for key in PHASES {
            let Some(ran) = report
                .phases
                .iter()
                .find(|p| super::blocked::phase_key(p.phase) == key)
            else {
                continue;
            };
            // Held to the caps its node's config said where it ran, else to those it was
            // placed under, as an older node's jobs were.
            let held = match &ran.caps {
                Some(f) => *f == c.fingerprint,
                None => placed,
            };
            if !held {
                continue;
            }
            since(out, node, day);
            let cov = out.coverage.entry((node.to_string(), key)).or_default();
            cov.ran = cov.ran.saturating_add(1);
            if ran.coverage == EgressCoverage::Complete {
                cov.complete = cov.complete.saturating_add(1);
            }
            let Some(p) = phase_of(c, key) else {
                continue;
            };
            // Each entry counts a job once, however many of its contacts it allows.
            let mut hit: BTreeSet<&str> = BTreeSet::new();
            for e in report.entries.iter().filter(|e| {
                super::blocked::phase_key(e.phase) == key
                    && matches!(
                        e.outcome,
                        EgressOutcome::Observed | EgressOutcome::WouldBlock
                    )
            }) {
                let Some(dest) = Dest::of(&e.destination) else {
                    continue;
                };
                if let Verdict::Allowed(entries) = verdict(p, &dest) {
                    hit.extend(entries);
                }
            }
            for e in hit {
                if let Some(u) = out.entries.get_mut(&(node.to_string(), key, e.to_string())) {
                    u.jobs = u.jobs.saturating_add(1);
                    u.last_day = Some(u.last_day.map_or(day, |d| d.max(day)));
                }
            }
        }
    }

    /// The use counted: cut when [`SCAN`] jobs were read and the last still fell within the
    /// window.
    pub fn finish(mut self) -> CapUse {
        self.out.capped = self.read >= SCAN && self.last_day.is_some_and(|d| d >= self.since);
        self.out
    }
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::*;

    use super::*;
    use crate::egress::testing::{entry, job, phase};
    use crate::server::Hub;
    use crate::store::Db;

    /// The use of `nodes`' caps' entries on day `today` (since the epoch).
    fn cap_use(hub: &Hub, nodes: &[(String, NodeRow)], today: u64) -> anyhow::Result<CapUse> {
        let mut scan = Scan::new(nodes, today);
        hub.db.visit_jobs(SCAN, |_, j| scan.visit(j))?;
        Ok(scan.finish())
    }

    /// A contact counts toward its node's cap entries that allow it, for the jobs placed under
    /// the caps it has now; an entry no contact matched has no observed use once a job reported
    /// the phase completely.
    #[test]
    fn a_contact_counts_toward_the_cap_entries_of_the_node_it_ran_on() {
        let db = std::sync::Arc::new(Db::open_memory().unwrap());
        let hub = Hub::new(db.clone(), None);
        let mut caps = EgressCaps::normalized(
            HubPhase::Unrestricted,
            false,
            HubPhase::Allow {
                names: vec!["debian.org".into(), "pypi.org".into()],
                ips: vec![],
            },
        )
        .unwrap();
        caps.fingerprint = "ab".repeat(32);
        let node = NodeRow {
            inventory: Some(vk_hub_proto::Inventory {
                egress_caps: Some(NodeEgressCaps::Listed(caps)),
                ..vk_hub_proto::Inventory::default()
            }),
            ..NodeRow::default()
        };
        let nodes = vec![("n1".to_string(), node)];
        let report = |coverage| EgressReport {
            entries: vec![EgressEntry {
                phase: EgressPhase::Build,
                ..entry(
                    EgressOutcome::Observed,
                    EgressProtocol::Dns,
                    EgressDestination::domain("deb.debian.org"),
                    None,
                )
            }],
            phases: vec![phase(EgressPhase::Build, coverage)],
            ..EgressReport::default()
        };
        for (n, fingerprint, coverage) in [
            (1, Some("ab".repeat(32)), EgressCoverage::Complete),
            // Under other caps, or none known: not counted.
            (2, Some("cd".repeat(32)), EgressCoverage::Complete),
            (3, None, EgressCoverage::Complete),
            // No report: counted apart.
            (4, Some("ab".repeat(32)), EgressCoverage::Complete),
            // Placed under other caps, held to these where it ran: counted.
            (5, Some("cd".repeat(32)), EgressCoverage::Complete),
            // Placed under these, held to others, or to more than one: not counted.
            (6, Some("ab".repeat(32)), EgressCoverage::Complete),
            (7, Some("ab".repeat(32)), EgressCoverage::Complete),
        ] {
            let mut report = report(coverage);
            for p in &mut report.phases {
                p.caps = match n {
                    5 => Some("ab".repeat(32)),
                    6 => Some("cd".repeat(32)),
                    7 => Some(UNKNOWN_CAPS.to_string()),
                    _ => None,
                };
            }
            let mut row = job(n, report);
            if n == 4 {
                row.result = None;
            }
            row.egress_caps = fingerprint;
            row.finished_at = Some(100 * 86_400);
            let id = format!("{n:032x}");
            let mut queued = row.clone();
            queued.result = None;
            db.submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
                .unwrap();
            db.put_job(&id, &row, &[], 11).unwrap();
        }
        let used = cap_use(&hub, &nodes, 110).unwrap();
        assert_eq!(used.standing("n1", "build", "debian.org"), Standing::Used);
        assert_eq!(used.unused("n1"), vec![("build", "pypi.org")]);
        assert_eq!(
            used.coverage[&("n1".to_string(), "build")],
            Coverage {
                ran: 2,
                complete: 2
            }
        );
        assert_eq!(used.since_day.get("n1"), Some(&100));
        assert_eq!(used.unreported.get("n1"), Some(&1));
        // Past the window: no evidence either way.
        let later = cap_use(&hub, &nodes, 100 + USE_DAYS).unwrap();
        assert_eq!(
            later.standing("n1", "build", "pypi.org"),
            Standing::NoEvidence
        );
    }
}
