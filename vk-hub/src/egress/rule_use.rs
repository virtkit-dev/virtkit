//! Which entries of the hub's egress rules jobs use (`docs/fleet-design.md`, *Egress page*,
//! *Observed traffic*): a contact of Observed traffic counts toward every entry of every rule
//! that allows it, a broad entry beside a narrow one, for the jobs that rule applies to now —
//! enforced, as the Fallback, or as a dry-run candidate — and that ran the phase. A contact a
//! dry-run allowlist would have blocked counts too: the switch carried it. An entry no contact
//! matched within [`USE_DAYS`] has *no observed use*, beside the coverage that qualifies it: how
//! many of the jobs it applies to reported the phase completely. Nothing is removed.
//!
//! Observed traffic keeps each project's contacts by phase, protection, ref and day, so which
//! rules apply is resolved per project, protection and ref from the rules as they stand now,
//! not as each job was placed. A record's day is the day a job first used the destination, on
//! its node's clock; a coverage record's the day the job ended, on the hub's.
//!
//! The scan is bounded: at most [`SCAN`] records of each table, and it says when it was cut.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use vk_hub_proto::egress::{EgressPhase, HubPhase};

use super::blocked::Subject;
use super::matching::{Dest, Verdict, verdict};
use super::observed::Contact;
use super::rules::claims_for;
use crate::server::Hub;
use crate::store::{EgressRuleRow, ObservedSubject, UNREPORTED, resolve_egress};

/// The days an entry's use is counted over.
pub const USE_DAYS: u64 = 30;

/// The most records read of each of Observed traffic's tables.
pub const SCAN: usize = 200_000;

/// The phases a rule lists entries for, by [`super::blocked::phase_key`].
pub const PHASES: [&str; 2] = ["run", "build"];

/// One entry's use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryUse {
    /// The jobs that used it within [`USE_DAYS`].
    pub jobs: u64,
    /// The latest day a job first used it on, as far back as the history goes.
    pub last_day: Option<u64>,
}

/// How completely the jobs a rule applies to reported a phase within [`USE_DAYS`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    pub ran: u64,
    pub complete: u64,
}

/// The rules' use, by rule name and phase.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleUse {
    /// Each entry's, by `(rule, phase, entry)`: every listed entry has one.
    pub entries: BTreeMap<(String, &'static str, String), EntryUse>,
    pub coverage: BTreeMap<(String, &'static str), Coverage>,
    /// The jobs a rule applies to that sent no report, within [`USE_DAYS`].
    pub unreported: BTreeMap<String, u64>,
    /// The contacts not kept, past their project's bound, of the projects a rule applies to.
    pub dropped: BTreeMap<String, u64>,
    /// How completely every job reported each phase within [`USE_DAYS`], whatever rules apply,
    /// and those that sent no report.
    pub reported: BTreeMap<&'static str, Coverage>,
    pub silent: u64,
    /// The first day the history's reports go back to.
    pub since_day: Option<u64>,
    /// Whether a bound cut what was read.
    pub capped: bool,
}

/// How an entry stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Used within [`USE_DAYS`].
    Used,
    /// No contact matched it within [`USE_DAYS`], with complete reports to say so.
    Unused,
    /// No contact matched it, and no job it applies to reported the phase completely.
    NoEvidence,
}

impl RuleUse {
    /// How entry `entry` of `rule`'s `phase` stands.
    pub fn standing(&self, rule: &str, phase: &'static str, entry: &str) -> Standing {
        let used = self
            .entries
            .get(&(rule.to_string(), phase, entry.to_string()))
            .is_some_and(|u| u.jobs > 0);
        let reported = self
            .coverage
            .get(&(rule.to_string(), phase))
            .is_some_and(|c| c.complete > 0);
        // A read cut short may have left out the very contact that matched.
        match (used, reported && !self.capped) {
            (true, _) => Standing::Used,
            (false, true) => Standing::Unused,
            (false, false) => Standing::NoEvidence,
        }
    }

    /// The entries of `rule` with no observed use, as `(phase, entry)`.
    pub fn unused(&self, rule: &str) -> Vec<(&'static str, &str)> {
        self.entries
            .keys()
            .filter(|(r, _, _)| r == rule)
            .filter(|(r, p, e)| self.standing(r, p, e) == Standing::Unused)
            .map(|(_, p, e)| (*p, e.as_str()))
            .collect()
    }
}

/// `rule`'s phase `key`.
pub fn phase_of<'a>(rule: &'a EgressRuleRow, key: &str) -> Option<&'a HubPhase> {
    match key {
        "run" => Some(&rule.run),
        "build" => Some(&rule.build),
        _ => None,
    }
}

/// The rules that apply to the jobs of `subject`'s `protection` and `git_ref`, by name:
/// enforced, as the Fallback, or as dry-run candidates.
fn applying(
    rules: &[EgressRuleRow],
    subjects: &HashMap<String, ObservedSubject>,
    param: &str,
    protection: &str,
    git_ref: &str,
) -> Vec<String> {
    let Some(subject) = Subject::parse(param) else {
        return Vec::new();
    };
    let path = subjects.get(param).and_then(|s| s.project.as_deref());
    let claims = claims_for(&subject, path, protection, git_ref);
    let layer = resolve_egress(rules, claims.as_ref());
    let mut out = layer.rules;
    out.extend(layer.dry_run.into_iter().map(|d| d.rule));
    out
}

/// The use of `rules`' entries, on day `today` (since the epoch).
pub fn rule_use(hub: &Hub, rules: &[EgressRuleRow], today: u64) -> Result<RuleUse> {
    let mut out = RuleUse::default();
    for r in rules {
        for key in PHASES {
            if let Some(HubPhase::Allow { names, ips }) = phase_of(r, key) {
                for e in names.iter().chain(ips) {
                    out.entries
                        .insert((r.name.clone(), key, e.clone()), EntryUse::default());
                }
            }
        }
    }
    let by_name: HashMap<&str, &EgressRuleRow> =
        rules.iter().map(|r| (r.name.as_str(), r)).collect();
    let subjects: HashMap<String, ObservedSubject> =
        hub.db.observed_subjects()?.into_iter().collect();
    let since = today.saturating_sub(USE_DAYS - 1);
    let mut seen: HashMap<(String, String, String), Vec<String>> = HashMap::new();
    let mut applied: BTreeSet<(String, String)> = BTreeSet::new();
    let mut apply = |param: &str, protection: &str, git_ref: &str| -> Vec<String> {
        let key = (
            param.to_string(),
            protection.to_string(),
            git_ref.to_string(),
        );
        let names = seen
            .entry(key)
            .or_insert_with(|| applying(rules, &subjects, param, protection, git_ref))
            .clone();
        for n in &names {
            applied.insert((n.clone(), param.to_string()));
        }
        names
    };
    let complete = hub.db.observed_records(SCAN, |r| {
        let Some(key) = PHASES.iter().copied().find(|k| *k == r.phase) else {
            return;
        };
        let Some(dest) = Contact::parse(&r.contact).and_then(|c| Dest::of(&c.destination)) else {
            return;
        };
        for name in apply(&r.subject, &r.protection, &r.git_ref) {
            let Some(p) = by_name
                .get(name.as_str())
                .and_then(|rule| phase_of(rule, key))
            else {
                continue;
            };
            let Verdict::Allowed(hits) = verdict(p, &dest) else {
                continue;
            };
            for e in hits {
                if let Some(u) = out.entries.get_mut(&(name.clone(), key, e.to_string())) {
                    u.last_day = Some(u.last_day.map_or(r.day, |d| d.max(r.day)));
                    // The day a job first used it: one that began the day before the window
                    // may have used it again within it, so that day counts too.
                    if r.day.saturating_add(1) >= since {
                        u.jobs = u.jobs.saturating_add(r.jobs);
                    }
                }
            }
        }
    })?;
    out.capped |= !complete;
    let complete = hub.db.coverage_records(SCAN, |r| {
        out.since_day = Some(out.since_day.map_or(r.day, |d| d.min(r.day)));
        if r.day < since {
            return;
        }
        if r.phase == UNREPORTED {
            out.silent = out.silent.saturating_add(r.jobs);
        } else if let Some(key) = PHASES.iter().copied().find(|k| *k == r.phase) {
            let c = out.reported.entry(key).or_default();
            c.ran = c.ran.saturating_add(r.jobs);
            c.complete = c.complete.saturating_add(r.complete);
        }
        let names = apply(&r.subject, &r.protection, &r.git_ref);
        if r.phase == UNREPORTED {
            for name in names {
                let n = out.unreported.entry(name).or_default();
                *n = n.saturating_add(r.jobs);
            }
            return;
        }
        let Some(key) = PHASES.iter().copied().find(|k| *k == r.phase) else {
            return;
        };
        for name in names {
            let c = out.coverage.entry((name, key)).or_default();
            c.ran = c.ran.saturating_add(r.jobs);
            c.complete = c.complete.saturating_add(r.complete);
        }
    })?;
    out.capped |= !complete;
    for (rule, param) in &applied {
        if let Some(s) = subjects.get(param).filter(|s| s.dropped > 0) {
            let n = out.dropped.entry(rule.clone()).or_default();
            *n = n.saturating_add(s.dropped);
        }
    }
    Ok(out)
}

/// How the current rules stand for a destination their jobs used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Compared {
    /// Allowed, by these rules and entries: `wab · debian.org`, `wab · unrestricted`.
    Allowed(Vec<String>),
    /// An address no IP range lists, in a phase that lists names.
    ByNameOnly,
    Outside,
}

/// How `rules` stand for `dest` in phase `key` for jobs of `subject`'s `protection` and
/// `git_ref`; `project` the path its latest job named.
pub fn compare(
    rules: &[EgressRuleRow],
    subject: &Subject,
    project: Option<&str>,
    protection: &str,
    git_ref: &str,
    key: &str,
    dest: &Dest,
) -> Compared {
    let claims = claims_for(subject, project, protection, git_ref);
    let layer = resolve_egress(rules, claims.as_ref());
    let phase = match key {
        "run" => EgressPhase::Run,
        "build" => EgressPhase::Build,
        _ => return Compared::Outside,
    };
    let Some(p) = layer.phase(phase) else {
        return Compared::Outside;
    };
    match verdict(p, dest) {
        Verdict::Unrestricted | Verdict::Allowed(_) => {}
        Verdict::ByNameOnly => return Compared::ByNameOnly,
        Verdict::Outside => return Compared::Outside,
    }
    let by = layer
        .rules
        .iter()
        .filter_map(|name| {
            let r = rules.iter().find(|r| r.name == *name)?;
            let label = match name.as_str() {
                crate::store::DEFAULT_RULE => "Fallback",
                n => n,
            };
            match verdict(phase_of(r, key)?, dest) {
                Verdict::Unrestricted => Some(format!("{label} · unrestricted")),
                Verdict::Allowed(hits) => Some(format!("{label} · {}", hits.join(", "))),
                _ => None,
            }
        })
        .collect();
    Compared::Allowed(by)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::testing::{entry, job, phase};
    use crate::store::{Db, RuleChange, RuleMode};
    use crate::subject::Subject as Selects;
    use vk_hub_proto::egress::*;

    fn allow(names: &[&str], ips: &[&str]) -> HubPhase {
        HubPhase::Allow {
            names: names.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A contact counts toward every entry that allows it, of every rule that applies to its
    /// jobs; an entry no contact matched has no observed use, unless no job it applies to
    /// reported the phase completely.
    #[test]
    fn a_contact_counts_toward_every_entry_that_allows_it() {
        let db = std::sync::Arc::new(Db::open_memory().unwrap());
        let hub = Hub::new(db.clone(), None);
        for (name, subject, build, mode) in [
            (
                "wab",
                Some("gitlab gl, projects acme/**"),
                allow(&["debian.org", "deb.debian.org", "pypi.org"], &[]),
                RuleMode::Enforce,
            ),
            (
                "dry",
                Some("gitlab gl, project-id 42"),
                allow(&["debian.org"], &[]),
                RuleMode::DryRun,
            ),
            (
                "other",
                Some("gitlab gl, project-id 7"),
                allow(&["debian.org"], &[]),
                RuleMode::Enforce,
            ),
        ] {
            let change = RuleChange {
                name: name.into(),
                subject: subject.map(|s| Selects::parse(s).unwrap()),
                run: Some(allow(&["corp.example.com"], &[])),
                build: Some(build),
                mode: Some(mode),
            };
            db.put_egress_rule(&change, false, "uid 1", 1).unwrap();
        }
        let mut row = job(
            1,
            EgressReport {
                entries: vec![EgressEntry {
                    phase: EgressPhase::Build,
                    first_seen_ms: 100 * crate::egress::observed::DAY_MS,
                    ..entry(
                        EgressOutcome::Observed,
                        EgressProtocol::Dns,
                        EgressDestination::domain("deb.debian.org"),
                        None,
                    )
                }],
                phases: vec![
                    phase(EgressPhase::Build, EgressCoverage::Complete),
                    phase(EgressPhase::Run, EgressCoverage::Partial),
                ],
                ..EgressReport::default()
            },
        );
        (row.gitlab, row.project_id, row.project) =
            (Some("gl".into()), Some(42), Some("acme/web".into()));
        row.finished_at = Some(100 * 86_400);
        let id = format!("{:032x}", 1);
        let mut queued = row.clone();
        queued.result = None;
        db.submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
            .unwrap();
        db.put_job(&id, &row, &[], 11).unwrap();

        let (_, rules) = db.egress_rules().unwrap();
        let used = rule_use(&hub, &rules, 110).unwrap();
        assert!(!used.capped);
        assert_eq!(used.since_day, Some(100));
        for (rule, entry) in [
            ("wab", "debian.org"),
            ("wab", "deb.debian.org"),
            ("dry", "debian.org"),
        ] {
            assert_eq!(
                used.standing(rule, "build", entry),
                Standing::Used,
                "{rule} {entry}"
            );
        }
        assert_eq!(used.unused("wab"), vec![("build", "pypi.org")]);
        let cut = RuleUse {
            capped: true,
            ..used.clone()
        };
        assert_eq!(
            cut.standing("wab", "build", "pypi.org"),
            Standing::NoEvidence
        );
        // Run reported only in part: its entries lack the evidence to say.
        assert_eq!(
            used.standing("wab", "run", "corp.example.com"),
            Standing::NoEvidence
        );
        // Not a rule of the project's: nothing applies, nothing counts.
        assert_eq!(
            used.standing("other", "build", "debian.org"),
            Standing::NoEvidence
        );
        assert_eq!(
            used.coverage.get(&("wab".to_string(), "build")),
            Some(&Coverage {
                ran: 1,
                complete: 1
            })
        );
        // Past the window: used once, but not lately.
        let edge = rule_use(&hub, &rules, 100 + USE_DAYS).unwrap();
        assert_eq!(
            edge.entries[&("wab".to_string(), "build", "debian.org".to_string())].jobs,
            1
        );
        let later = rule_use(&hub, &rules, 101 + USE_DAYS).unwrap();
        assert_eq!(
            later.standing("wab", "build", "debian.org"),
            Standing::NoEvidence
        );
        assert_eq!(
            later.entries[&("wab".to_string(), "build", "debian.org".to_string())].last_day,
            Some(100)
        );

        let subject = Subject::Gitlab {
            instance: "gl".into(),
            project_id: 42,
        };
        let deb = Dest::Name("deb.debian.org".into());
        assert_eq!(
            compare(
                &rules,
                &subject,
                Some("acme/web"),
                "unknown",
                "main",
                "build",
                &deb
            ),
            Compared::Allowed(vec!["wab · debian.org, deb.debian.org".into()])
        );
        let pypi = Dest::Name("files.pythonhosted.org".into());
        assert_eq!(
            compare(
                &rules,
                &subject,
                Some("acme/web"),
                "unknown",
                "main",
                "build",
                &pypi
            ),
            Compared::Outside
        );
    }
}
