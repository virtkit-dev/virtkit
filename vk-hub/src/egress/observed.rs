//! The Egress page's *Observed traffic* (`docs/fleet-design.md`, *Egress page*): what the jobs of
//! the history reached, from their nodes' reports — contacts allowed, and those a dry-run
//! allowlist would have refused and the switch carried — by project, phase, protection, ref and
//! day, each destination exact, so that a hub rule's entries can later be matched against every
//! contact they allow; and how completely each job reported each phase it ran. A job's part is a
//! pure function of its record ([`observation`]), so the store adds it as the record is written
//! and takes it back as the record leaves the history, as it does a Blocked row's share.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use vk_hub_proto::client::JobState;
use vk_hub_proto::egress::{
    EgressCoverage, EgressDestination, EgressEntry, EgressOutcome, EgressProtocol,
};

use super::blocked::{Subject, phase_key};
use crate::store::JobRow;

/// A destination as a job's guests used it: reached, or carried while a dry-run allowlist would
/// have refused it; its protocol and destination exact, a port kept and a domain never merged
/// into a suffix.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Contact {
    pub outcome: EgressOutcome,
    pub protocol: EgressProtocol,
    pub destination: EgressDestination,
}

impl Contact {
    /// What entry `e` used; `None` for an attempt the switch refused.
    pub fn of(e: &EgressEntry) -> Option<Contact> {
        matches!(
            e.outcome,
            EgressOutcome::Observed | EgressOutcome::WouldBlock
        )
        .then(|| Contact {
            outcome: e.outcome,
            protocol: e.protocol,
            destination: e.destination.clone(),
        })
    }

    /// As the store's keys hold it: JSON, read back by [`Contact::parse`].
    pub fn key(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse(key: &str) -> Option<Contact> {
        serde_json::from_str(key).ok()
    }

    /// In words: `DNS crates.io`, `TCP 10.0.0.1:443`. Holds a guest's strings, bounded and with
    /// their control characters replaced on the node.
    pub fn text(&self) -> String {
        format!(
            "{} {}",
            super::protocol_text(self.protocol),
            super::destination_text(&self.destination)
        )
    }
}

/// A job's protection as the store's keys hold it, and as the page's filter names it.
pub fn protection_key(protected: Option<bool>) -> &'static str {
    match protected {
        Some(true) => "protected",
        Some(false) => "unprotected",
        None => "unknown",
    }
}

/// Every [`protection_key`] with its label, in the filter's order.
pub const PROTECTIONS: [(&str, &str); 3] = [
    ("protected", "Protected refs"),
    ("unprotected", "Unprotected refs"),
    ("unknown", "Protection not reported"),
];

/// What a job's report said of one contact in one phase, across its VMs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Use {
    pub attempts: u64,
    /// The first and last attempt, in milliseconds since the epoch on its node's clock.
    pub first_ms: u64,
    pub last_ms: u64,
}

/// How a job stands for Observed traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reported {
    /// It ran and its node sent no report: what it reached is unknown.
    No,
    /// Its node's report, of a running job what it recorded so far.
    Yes {
        /// Each phase it ran, by [`phase_key`], and whether the node recorded all of it.
        phases: BTreeMap<&'static str, bool>,
        /// Its contacts by phase and [`Contact::key`].
        uses: BTreeMap<(&'static str, String), Use>,
    },
}

/// One job's part of Observed traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub subject: Subject,
    pub protection: &'static str,
    /// Its ref; empty when it named none.
    pub git_ref: String,
    /// When it ended, on the hub's clock, or was last heard of.
    pub at: u64,
    pub reported: Reported,
}

/// Milliseconds in a day: what a contact's day is counted by.
pub const DAY_MS: u64 = 86_400_000;

impl Observation {
    /// The day of `at`, in days since the epoch: what its coverage is counted by.
    pub fn day(&self) -> u64 {
        self.at / 86_400
    }

    /// The day contact `u` was first seen in, on its node's clock; the job's own day when the
    /// node gave no time.
    pub fn use_day(&self, u: &Use) -> u64 {
        match u.first_ms {
            0 => self.day(),
            ms => ms / DAY_MS,
        }
    }
}

/// Job `j`'s part of Observed traffic: `None` for a job that has not run on a node, and for
/// one running whose node has sent no report yet.
pub fn observation(j: &JobRow) -> Option<Observation> {
    let reported = match super::network(j) {
        super::Network::NotRun | super::Network::Pending => return None,
        super::Network::Unavailable => Reported::No,
        super::Network::Reported(report) => {
            let phases = report
                .phases
                .iter()
                .map(|p| (phase_key(p.phase), p.coverage == EgressCoverage::Complete))
                .collect();
            let mut uses: BTreeMap<(&'static str, String), Use> = BTreeMap::new();
            for e in &report.entries {
                let Some(contact) = Contact::of(e) else {
                    continue;
                };
                let u = uses
                    .entry((phase_key(e.phase), contact.key()))
                    .or_insert(Use {
                        attempts: 0,
                        first_ms: e.first_seen_ms,
                        last_ms: e.last_seen_ms,
                    });
                u.attempts = u.attempts.saturating_add(e.count);
                u.first_ms = u.first_ms.min(e.first_seen_ms);
                u.last_ms = u.last_ms.max(e.last_seen_ms);
            }
            Reported::Yes { phases, uses }
        }
    };
    // A running job's place in time is its start; it moves to its end once it has one.
    let at = match j.state {
        JobState::Finished => j.finished_at,
        _ => None,
    }
    .or(j.started_at)
    .unwrap_or(j.created_at);
    Some(Observation {
        subject: Subject::of(j),
        protection: protection_key(j.protected),
        git_ref: j.git_ref.clone().unwrap_or_default(),
        at,
        reported,
    })
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::{EgressCoverage, EgressLayer, EgressPhase, EgressReport};

    use super::*;
    use crate::egress::testing::{entry, job, phase};

    /// A job's contacts are its reached and dry-run-carried entries, by phase and exact
    /// destination, summed across VMs with their first and last attempt; a refused attempt is
    /// not one. Each phase it ran says whether it was recorded whole.
    #[test]
    fn a_job_observes_what_it_reached_by_phase_and_destination() {
        use EgressOutcome::*;
        let domain = |n: &str| EgressDestination::domain(n);
        let mut j = job(
            1,
            EgressReport {
                entries: vec![
                    entry(Observed, EgressProtocol::Dns, domain("a.example"), None),
                    EgressEntry {
                        count: 3,
                        first_seen_ms: 500,
                        last_seen_ms: 2_000_000,
                        source: vk_hub_proto::egress::EgressSource::Service { name: "db".into() },
                        ..entry(Observed, EgressProtocol::Dns, domain("a.example"), None)
                    },
                    EgressEntry {
                        phase: EgressPhase::Build,
                        ..entry(Observed, EgressProtocol::Dns, domain("a.example"), None)
                    },
                    entry(
                        WouldBlock,
                        EgressProtocol::Tcp,
                        EgressDestination::address("10.0.0.1:443"),
                        Some(EgressLayer::Job),
                    ),
                    entry(
                        Blocked,
                        EgressProtocol::Dns,
                        domain("b.example"),
                        Some(EgressLayer::NodeCap),
                    ),
                ],
                phases: vec![
                    phase(EgressPhase::Run, EgressCoverage::Complete),
                    phase(EgressPhase::Build, EgressCoverage::Partial),
                ],
                ..EgressReport::default()
            },
        );
        j.protected = Some(true);
        let o = observation(&j).unwrap();
        assert_eq!(
            (o.protection, o.git_ref.as_str(), o.at, o.day()),
            ("protected", "main", 1_001, 0)
        );
        let Reported::Yes { phases, uses } = &o.reported else {
            panic!("not reported: {o:?}");
        };
        assert_eq!(phases, &BTreeMap::from([("build", false), ("run", true)]));
        assert_eq!(uses.len(), 3, "{uses:?}");
        let a = Contact {
            outcome: Observed,
            protocol: EgressProtocol::Dns,
            destination: domain("a.example"),
        };
        assert_eq!(
            uses[&("run", a.key())],
            Use {
                attempts: 4,
                first_ms: 500,
                last_ms: 2_000_000
            }
        );
        assert!(uses.contains_key(&("build", a.key())));
        let (_, carried) = uses
            .keys()
            .find(|(p, k)| *p == "run" && *k != a.key())
            .unwrap();
        let carried = Contact::parse(carried).unwrap();
        assert_eq!(
            (carried.outcome, carried.text()),
            (WouldBlock, "TCP 10.0.0.1:443".to_string())
        );
        assert_eq!(o.use_day(&uses[&("run", a.key())]), 0);
        assert_eq!(
            o.use_day(&Use {
                attempts: 1,
                first_ms: 3 * DAY_MS + 1,
                last_ms: 0
            }),
            3
        );

        // Ended with no report: unknown, not nothing.
        j.result.as_mut().unwrap().egress = None;
        assert_eq!(observation(&j).unwrap().reported, Reported::No);
        // Never run: no part at all.
        j.started_at = None;
        assert_eq!(observation(&j), None);
    }
}
