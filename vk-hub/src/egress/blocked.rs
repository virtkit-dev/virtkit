//! The Egress page's *Blocked* rows (`docs/fleet-design.md`, *Egress page*): the denials and
//! declaration refusals of the jobs in the history, gathered by what was refused and whose
//! jobs refused it. A job's share of each row is a pure function of its record ([`shares`]),
//! so the store adds it as the record is written and takes it back as the record leaves the
//! history, and a record written again with the same report changes nothing.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vk_hub_proto::egress::{
    EgressDestination, EgressDimension, EgressEntry, EgressLayer, EgressOutcome, EgressPhase,
    EgressProtocol, EgressRefusal,
};

use crate::store::JobRow;

/// Whose jobs a row gathers.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    /// A project, by GitLab's ID, of the instance its jobs' relay is bound to: the approval gate
    /// held the claim to that instance.
    Gitlab { instance: String, project_id: u64 },
    /// Every job of a key bound to no GitLab instance, whose projects are its own claim: an
    /// older hub's.
    Key { key: String },
}

impl Subject {
    /// Whose job `j` is.
    pub fn of(j: &JobRow) -> Subject {
        match (&j.gitlab, j.project_id) {
            (Some(instance), Some(project_id)) => Subject::Gitlab {
                instance: instance.clone(),
                project_id,
            },
            _ => Subject::Key { key: j.key.clone() },
        }
    }

    /// As a query's value and a mute's key: `gitlab:<instance>:<project ID>`, `key:<key ID>`.
    pub fn param(&self) -> String {
        match self {
            Subject::Gitlab {
                instance,
                project_id,
            } => format!("gitlab:{instance}:{project_id}"),
            Subject::Key { key } => format!("key:{key}"),
        }
    }

    /// The subject [`Subject::param`] wrote `s` for.
    pub fn parse(s: &str) -> Option<Subject> {
        if let Some(rest) = s.strip_prefix("gitlab:") {
            let (instance, id) = rest.rsplit_once(':')?;
            let project_id = id.parse().ok().filter(|&id| id > 0)?;
            return crate::store::valid_gitlab_name(instance).then(|| Subject::Gitlab {
                instance: instance.to_string(),
                project_id,
            });
        }
        let key = s.strip_prefix("key:")?;
        vk_hub_proto::valid_sha256(key).then(|| Subject::Key {
            key: key.to_string(),
        })
    }

    /// Whether it is a project, or every job of a key.
    pub fn is_project(&self) -> bool {
        matches!(self, Subject::Gitlab { .. })
    }

    /// In words, with the display-safe `project` its latest job named and its key's
    /// `key_name`: `acme/web on gl`, `project 42 on gl`, `key ci`.
    pub fn text(&self, project: Option<&str>, key_name: &str) -> String {
        match (self, project) {
            (Subject::Gitlab { instance, .. }, Some(p)) => format!("{p} on {instance}"),
            (
                Subject::Gitlab {
                    instance,
                    project_id,
                },
                None,
            ) => format!("project {project_id} on {instance}"),
            (Subject::Key { .. }, _) => format!("key {key_name}"),
        }
    }
}

/// Which of the page's separate views a row is in, each with its own counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    Blocked,
    WouldBlock,
    /// Declaration issues: nothing was attempted. An invalid entry failed its job; one a layer
    /// above leaves nothing of did not.
    Refused,
}

impl View {
    pub const ALL: [View; 3] = [View::Blocked, View::WouldBlock, View::Refused];

    /// The query's value.
    pub fn name(self) -> &'static str {
        match self {
            View::Blocked => "blocked",
            View::WouldBlock => "would_block",
            View::Refused => "refused",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            View::Blocked => "Blocked",
            View::WouldBlock => "Would block",
            View::Refused => "Declaration issues",
        }
    }

    pub fn parse(s: &str) -> Option<View> {
        View::ALL.into_iter().find(|v| v.name() == s)
    }
}

/// What a row is of: a destination denied, or an allow entry declared and refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Finding {
    /// Its protocol and destination, a port kept and a domain never merged into a suffix.
    Denial {
        view: View,
        protocol: EgressProtocol,
        destination: EgressDestination,
    },
    Refusal {
        variable: String,
        dimension: EgressDimension,
        entry: String,
    },
}

impl Finding {
    /// What denial `e` is of; `None` for an observed contact. An outcome from a later peer counts
    /// as blocked, as the job's own summary counts it.
    pub fn denial(e: &EgressEntry) -> Option<Finding> {
        let view = match e.outcome {
            EgressOutcome::Observed => return None,
            EgressOutcome::WouldBlock => View::WouldBlock,
            EgressOutcome::Blocked | EgressOutcome::Other => View::Blocked,
        };
        Some(Finding::Denial {
            view,
            protocol: e.protocol,
            destination: e.destination.clone(),
        })
    }

    /// What refusal `r` is of.
    pub fn refusal(r: &EgressRefusal) -> Finding {
        Finding::Refusal {
            variable: r.variable.clone(),
            dimension: r.dimension,
            entry: r.entry.clone(),
        }
    }

    pub fn view(&self) -> View {
        match self {
            Finding::Denial { view, .. } => *view,
            Finding::Refusal { .. } => View::Refused,
        }
    }

    /// In words: `TCP 10.0.0.1:443`, `MICROVM_EGRESS_ALLOW_NAME evil.com`. Holds a guest's
    /// strings, bounded and with their control characters replaced on the node.
    pub fn text(&self) -> String {
        match self {
            Finding::Denial {
                protocol,
                destination,
                ..
            } => format!(
                "{} {}",
                super::protocol_text(*protocol),
                super::destination_text(destination)
            ),
            Finding::Refusal {
                variable, entry, ..
            } => format!("{variable} {entry}"),
        }
    }
}

/// The ID of the row of `finding` by `subject`, 32 hex digits: derived, so a job's page links
/// to its rows without asking the store, and stable across hubs.
pub fn row_id(subject: &Subject, finding: &Finding) -> String {
    // A fixed tag, so a later change of what identifies a row makes other IDs.
    let encoded = serde_json::to_vec(&("blocked/1", subject, finding)).unwrap_or_default();
    let digest = Sha256::digest(&encoded);
    vk_hub_proto::to_hex(digest.get(..vk_hub_proto::ID_BYTES).unwrap_or_default())
}

/// What one job puts in a row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub subject: Subject,
    pub finding: Finding,
    /// Attempts it recorded; 0 for a refusal, which attempted nothing.
    pub attempts: u64,
    /// The layers that decided it, as [`layer_key`] names them.
    pub layers: BTreeSet<&'static str>,
    /// The phases it was seen in, as [`phase_key`] names them.
    pub phases: BTreeSet<&'static str>,
    /// When the job ended, on the hub's clock, or was last heard of: what orders a row's jobs.
    pub at: u64,
}

/// A layer as the page's filter names it: `node_cap`, `hub_rule`, `job`, `service`,
/// `unknown` for none or one the node could not tell.
pub fn layer_key(layer: Option<EgressLayer>) -> &'static str {
    layer.unwrap_or(EgressLayer::Unknown).as_str()
}

/// Every [`layer_key`], in the filter's order.
pub const LAYERS: [&str; 5] = ["node_cap", "hub_rule", "job", "service", "unknown"];

/// The layer named `key` in words, as a row's *blocked by* says it.
pub fn layer_label(key: &str) -> &'static str {
    match key {
        "node_cap" => "the node's cap",
        "hub_rule" => "a hub rule",
        "job" => "the job's narrowing",
        "service" => "a service's narrowing",
        _ => "an unknown layer",
    }
}

/// A phase as the page's filter names it.
pub fn phase_key(phase: EgressPhase) -> &'static str {
    match phase {
        EgressPhase::Run => "run",
        EgressPhase::Build => "build",
        EgressPhase::Other => "other",
    }
}

/// Every [`phase_key`] with its label, in the filter's order.
pub const PHASES: [(&str, &str); 3] = [("run", "Run"), ("build", "Build"), ("other", "Other")];

/// Job `j`'s share of each row, by row ID: one per distinct finding, its attempts summed
/// across phases and VMs, of the report it has, a running job's so far. Nothing for a job
/// without a report.
pub fn shares(j: &JobRow) -> BTreeMap<String, Share> {
    let mut out = BTreeMap::new();
    let Some(report) = super::report(j) else {
        return out;
    };
    let subject = Subject::of(j);
    let at = j.finished_at.or(j.started_at).unwrap_or(j.created_at);
    let mut share = |finding: Finding, attempts: u64, layer, phase| {
        let id = row_id(&subject, &finding);
        let s = out.entry(id).or_insert_with(|| Share {
            subject: subject.clone(),
            finding,
            attempts: 0,
            layers: BTreeSet::new(),
            phases: BTreeSet::new(),
            at,
        });
        s.attempts = s.attempts.saturating_add(attempts);
        s.layers.insert(layer_key(layer));
        s.phases.insert(phase_key(phase));
    };
    for e in &report.entries {
        if let Some(finding) = Finding::denial(e) {
            share(finding, e.count, e.layer, e.phase);
        }
    }
    for r in &report.refusals {
        share(Finding::refusal(r), 0, r.layer, r.phase);
    }
    out
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::{EgressReport, EgressSource, RefusalReason};

    use super::*;
    use crate::egress::testing::{entry, job};

    fn reported(entries: Vec<EgressEntry>) -> JobRow {
        job(
            1,
            EgressReport {
                entries,
                ..EgressReport::default()
            },
        )
    }

    /// A job's denials are shared by destination, summed across phases and VMs, an observed
    /// contact left out; refusals apart, attempting nothing; a bound key's job by project, an
    /// unbound key's by key.
    #[test]
    fn a_job_shares_its_denials_by_destination_and_subject() {
        use EgressOutcome::*;
        let domain = |n: &str| EgressDestination::domain(n);
        let cap = Some(EgressLayer::NodeCap);
        let mut j = reported(vec![
            entry(Blocked, EgressProtocol::Dns, domain("a.example"), cap),
            EgressEntry {
                phase: EgressPhase::Build,
                source: EgressSource::Service { name: "db".into() },
                count: 4,
                ..entry(
                    Blocked,
                    EgressProtocol::Dns,
                    domain("a.example"),
                    Some(EgressLayer::Service),
                )
            },
            entry(Other, EgressProtocol::Dns, domain("a.example"), None),
            entry(WouldBlock, EgressProtocol::Dns, domain("a.example"), cap),
            entry(Observed, EgressProtocol::Dns, domain("b.example"), None),
        ]);
        if let Some(r) = j.result.as_mut().and_then(|r| r.egress.as_mut()) {
            r.refusals.push(vk_hub_proto::egress::EgressRefusal {
                variable: "MICROVM_EGRESS_ALLOW_NAME".into(),
                entry: "evil.com".into(),
                dimension: EgressDimension::Name,
                phase: EgressPhase::Run,
                source: EgressSource::Job,
                layer: cap,
                reason: RefusalReason::Unreachable,
            });
        }
        let shares = shares(&j);
        let by_view = |v: View| -> Vec<&Share> {
            shares.values().filter(|s| s.finding.view() == v).collect()
        };
        let blocked = by_view(View::Blocked);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].attempts, 6);
        assert_eq!(
            blocked[0].layers,
            BTreeSet::from(["node_cap", "service", "unknown"])
        );
        assert_eq!(blocked[0].phases, BTreeSet::from(["build", "run"]));
        assert_eq!(by_view(View::WouldBlock).len(), 1);
        let refused = by_view(View::Refused);
        assert_eq!((refused.len(), refused[0].attempts), (1, 0));
        assert_eq!(
            refused[0].finding.text(),
            "MICROVM_EGRESS_ALLOW_NAME evil.com"
        );
        assert_eq!(blocked[0].subject, Subject::Key { key: "k".into() });
        assert_eq!(blocked[0].finding.text(), "DNS a.example");

        // Bound, the same denial is another row: the project's.
        j.gitlab = Some("gl".into());
        j.project_id = Some(42);
        let bound = super::shares(&j);
        let subject = Subject::Gitlab {
            instance: "gl".into(),
            project_id: 42,
        };
        assert!(bound.values().all(|s| s.subject == subject));
        assert!(bound.keys().all(|id| !shares.contains_key(id)));
        assert!(bound.keys().all(|id| vk_hub_proto::valid_id(id)));
        assert!(
            {
                let mut none = reported(vec![]);
                none.result = None;
                super::shares(&none)
            }
            .is_empty()
        );
    }

    #[test]
    fn a_subject_reads_back_from_its_param() {
        for s in [
            Subject::Gitlab {
                instance: "gl".into(),
                project_id: 42,
            },
            Subject::Key {
                key: "a".repeat(64),
            },
        ] {
            assert_eq!(Subject::parse(&s.param()), Some(s));
        }
        for bad in [
            "gitlab:gl:0",
            "gitlab:gl",
            "gitlab::4",
            "key:abc",
            "nothing",
            "gitlab:g l:4",
        ] {
            assert_eq!(Subject::parse(bad), None, "{bad}");
        }
    }
}
