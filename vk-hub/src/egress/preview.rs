//! What a change to the hub's egress rules would do, before it is saved (`docs/fleet-design.md`,
//! *Rules on the page*): the recent jobs whose layer it changes or that the rule selects, each
//! group of them with its layer before and after, both resolved with [`resolve_egress`] from
//! their records' claims; and the destinations Observed traffic holds that the change would
//! block, with how completely the jobs it affects reported, so that no reports never reads as
//! nothing to lose.
//!
//! A dry-run rule blocks nothing: a change that leaves one in dry-run, or adds one, is compared
//! as it would be enforced, which is what its jobs' reports then show as would-block.
//!
//! Every read is bounded: the latest [`JOB_SCAN`] jobs, [`OBSERVED_SCAN`] records of each of
//! Observed traffic's tables; what is shown is bounded apart, and each says when it was cut.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use vk_hub_proto::egress::{EgressPhase, HubEgress};

use super::blocked::Subject;
use super::matching::{Dest, Verdict, verdict};
use super::observed::Contact;
use super::rules::{claims_for, claims_of};
use crate::server::Hub;
use crate::store::{EgressRuleRow, RuleMode, UNREPORTED, resolve_egress};
use crate::subject::JobClaims;

/// The latest jobs of the history a preview reads.
pub const JOB_SCAN: usize = 1000;
/// The most groups of jobs a preview lists.
pub const MAX_GROUPS: usize = 200;
/// The most records a preview reads of each of Observed traffic's tables.
pub const OBSERVED_SCAN: usize = 200_000;
/// The most destinations a preview lists as lost.
pub const MAX_LOST: usize = 200;

/// The change previewed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit {
    /// Rule `.name` added, or changed to this.
    Put(Box<EgressRuleRow>),
    /// Rule removed.
    Remove(String),
}

impl Edit {
    pub fn name(&self) -> &str {
        match self {
            Edit::Put(r) => &r.name,
            Edit::Remove(name) => name,
        }
    }
}

/// `rules` with `edit` made, and those to compare `rules` with: the same, but for a rule left
/// or added in dry-run, which is compared as enforced.
pub fn apply(
    rules: &[EgressRuleRow],
    edit: &Edit,
) -> (Vec<EgressRuleRow>, Vec<EgressRuleRow>, bool) {
    let mut after: Vec<EgressRuleRow> = rules
        .iter()
        .filter(|r| r.name != edit.name())
        .cloned()
        .collect();
    let mut compared = after.clone();
    let mut as_enforced = false;
    if let Edit::Put(r) = edit {
        after.push((**r).clone());
        let was_enforced = rules
            .iter()
            .any(|o| o.name == r.name && o.mode == RuleMode::Enforce);
        let mut c = (**r).clone();
        if r.mode == RuleMode::DryRun && !was_enforced {
            c.mode = RuleMode::Enforce;
            as_enforced = true;
        }
        compared.push(c);
    }
    (after, compared, as_enforced)
}

/// Some jobs alike: of one GitLab instance's project, ref and protection, or of keys bound to
/// none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Their claims; `None` for jobs of keys bound to no GitLab instance.
    pub claims: Option<JobClaims>,
    /// The display-safe project their latest job named.
    pub project: Option<String>,
    /// Whether GitLab reported their ref's protection.
    pub protection_known: bool,
    pub jobs: u64,
    /// Their latest job's ID.
    pub latest: String,
    pub before: HubEgress,
    pub after: HubEgress,
    /// Why the jobs could not be placed under `after`, if they could not.
    pub unplaceable: Option<String>,
}

/// A destination of Observed traffic the change would refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lost {
    pub subject: Subject,
    /// Its project in words ([`Subject::text`]).
    pub who: String,
    pub phase: String,
    pub contact: Contact,
    /// The jobs that used it, and the latest day one first did, on its node's clock.
    pub jobs: u64,
    pub last_day: u64,
    /// An address the change refuses unless a lookup of a listed name resolved to it.
    pub uncertain: bool,
}

/// What a change would do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    /// The rules' generation it was made against: Save is refused once they move on.
    pub generation: u64,
    /// The change compared with a dry-run rule as enforced.
    pub as_enforced: bool,
    pub groups: Vec<Group>,
    /// Groups not listed past [`MAX_GROUPS`].
    pub more_groups: usize,
    /// The jobs read, and whether the history holds more than were.
    pub jobs_read: usize,
    pub jobs_capped: bool,
    /// What Observed traffic holds that it would refuse; and what it would refuse unless a
    /// lookup of a listed name resolved to it.
    pub lost: Vec<Lost>,
    pub maybe_lost: Vec<Lost>,
    pub more_lost: usize,
    /// Each phase whose access the change alters for some jobs, by
    /// [`super::blocked::phase_key`]: those of its jobs that ran it within the history, and of
    /// them those that reported it completely. Then the jobs it affects that sent no report.
    pub affected: BTreeMap<&'static str, Evidence>,
    pub affected_unreported: u64,
    /// Whether a bound cut what was read of Observed traffic.
    pub observed_capped: bool,
}

/// How completely the jobs whose access a change alters reported one phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evidence {
    pub ran: u64,
    pub complete: u64,
}

/// The phase key of [`super::blocked::phase_key`] as a layer's phase.
fn phase_of(key: &str) -> Option<EgressPhase> {
    match key {
        "run" => Some(EgressPhase::Run),
        "build" => Some(EgressPhase::Build),
        _ => None,
    }
}

/// The phases, by key, whose layer differs between `before` and `after`.
fn altered(before: &HubEgress, after: &HubEgress) -> impl Iterator<Item = &'static str> {
    [("run", EgressPhase::Run), ("build", EgressPhase::Build)]
        .into_iter()
        .filter(move |(_, p)| before.phase(*p) != after.phase(*p))
        .map(|(k, _)| k)
}

/// What groups jobs alike: their claims, the GitLab instance's name, project ID and path, ref
/// and protection; `None` for keys bound to no instance.
type ClaimsKey = Option<(String, u64, String, String, bool)>;

fn key_of(claims: Option<&JobClaims>) -> ClaimsKey {
    claims.map(|c| {
        (
            c.gitlab.clone(),
            c.project_id,
            c.project_path.clone(),
            c.git_ref.clone(),
            c.protected,
        )
    })
}

/// Resolve and remember the layers before and after for `claims`.
struct Layers<'a> {
    before: &'a [EgressRuleRow],
    after: &'a [EgressRuleRow],
    seen: HashMap<ClaimsKey, (HubEgress, HubEgress)>,
}

impl<'a> Layers<'a> {
    fn new(before: &'a [EgressRuleRow], after: &'a [EgressRuleRow]) -> Self {
        Layers {
            before,
            after,
            seen: HashMap::new(),
        }
    }

    fn of(&mut self, claims: Option<&JobClaims>) -> &(HubEgress, HubEgress) {
        let key = key_of(claims);
        let (before, after) = (self.before, self.after);
        self.seen.entry(key).or_insert_with(|| {
            (
                resolve_egress(before, claims),
                resolve_egress(after, claims),
            )
        })
    }
}

/// What `edit` to `rules`, at `generation`, would do.
pub fn preview(
    hub: &Hub,
    generation: u64,
    rules: &[EgressRuleRow],
    edit: &Edit,
) -> Result<Preview> {
    let (_, compared, as_enforced) = apply(rules, edit);
    let mut layers = Layers::new(rules, &compared);
    let name = edit.name();
    let names = |l: &HubEgress| {
        l.rules.iter().any(|r| r == name) || l.dry_run.iter().any(|d| d.rule == name)
    };

    // The recent jobs, grouped by claims, in the order of their latest job.
    let jobs = hub.db.jobs(JOB_SCAN)?;
    let mut affected: BTreeMap<&'static str, Evidence> = BTreeMap::new();
    let mut groups: Vec<Group> = Vec::new();
    let mut at: HashMap<ClaimsKey, usize> = HashMap::new();
    for (id, j) in &jobs {
        let claims = claims_of(j);
        let (before, after) = layers.of(claims.as_ref()).clone();
        if before == after && !names(&before) && !names(&after) {
            continue;
        }
        for key in altered(&before, &after) {
            affected.entry(key).or_default();
        }
        let key = key_of(claims.as_ref());
        match at.get(&key) {
            Some(&i) => {
                if let Some(g) = groups.get_mut(i) {
                    g.jobs = g.jobs.saturating_add(1);
                    g.protection_known &= j.protected.is_some();
                }
            }
            None => {
                at.insert(key, groups.len());
                let unplaceable = after.check().err();
                groups.push(Group {
                    claims,
                    project: j.project.clone(),
                    protection_known: j.protected.is_some(),
                    jobs: 1,
                    latest: id.clone(),
                    before,
                    after,
                    unplaceable,
                });
            }
        }
    }
    let more_groups = groups.len().saturating_sub(MAX_GROUPS);
    groups.truncate(MAX_GROUPS);

    // Observed traffic: each project, protection and ref whose layer changes.
    let subjects: HashMap<String, crate::store::ObservedSubject> =
        hub.db.observed_subjects()?.into_iter().collect();
    let claims_at = |param: &str, protection: &str, git_ref: &str| {
        let subject = Subject::parse(param)?;
        let path = subjects.get(param).and_then(|s| s.project.as_deref());
        Some((
            subject.clone(),
            claims_for(&subject, path, protection, git_ref),
        ))
    };
    let mut lost: BTreeMap<(String, String, String, bool), Lost> = BTreeMap::new();
    let mut observed_capped = !hub.db.observed_records(OBSERVED_SCAN, |r| {
        let Some(phase) = phase_of(&r.phase) else {
            return;
        };
        let Some((subject, claims)) = claims_at(&r.subject, &r.protection, &r.git_ref) else {
            return;
        };
        let Some(contact) = Contact::parse(&r.contact) else {
            return;
        };
        let Some(dest) = Dest::of(&contact.destination) else {
            return;
        };
        let (before, after) = layers.of(claims.as_ref());
        let (Some(b), Some(a)) = (before.phase(phase), after.phase(phase)) else {
            return;
        };
        if !verdict(b, &dest).allows() {
            return;
        }
        let maybe = match verdict(a, &dest) {
            v if v.allows() => return,
            Verdict::ByNameOnly => true,
            _ => false,
        };
        let l = lost
            .entry((r.subject.clone(), r.phase.clone(), r.contact.clone(), maybe))
            .or_insert_with(|| Lost {
                who: match subjects.get(&r.subject) {
                    Some(s) => subject.text(s.project.as_deref(), &s.key_name),
                    None => r.subject.clone(),
                },
                subject,
                phase: r.phase.clone(),
                contact,
                jobs: 0,
                last_day: 0,
                uncertain: maybe,
            });
        l.jobs = l.jobs.saturating_add(r.jobs);
        l.last_day = l.last_day.max(r.day);
    })?;
    let mut unreported = 0u64;
    observed_capped |= !hub.db.coverage_records(OBSERVED_SCAN, |r| {
        let Some((_, claims)) = claims_at(&r.subject, &r.protection, &r.git_ref) else {
            return;
        };
        let (before, after) = layers.of(claims.as_ref());
        if r.phase == UNREPORTED {
            if before != after {
                unreported = unreported.saturating_add(r.jobs);
            }
            return;
        }
        if let Some(key) = altered(before, after).find(|k| *k == r.phase) {
            let e = affected.entry(key).or_default();
            e.ran = e.ran.saturating_add(r.jobs);
            e.complete = e.complete.saturating_add(r.complete);
        }
    })?;
    let mut lost: Vec<Lost> = lost.into_values().collect();
    lost.sort_by(|a, b| b.jobs.cmp(&a.jobs).then(b.last_day.cmp(&a.last_day)));
    let (mut maybe_lost, mut lost): (Vec<Lost>, Vec<Lost>) =
        lost.into_iter().partition(|l| l.uncertain);
    let more_lost = lost.len().saturating_sub(MAX_LOST);
    lost.truncate(MAX_LOST);
    maybe_lost.truncate(MAX_LOST);
    Ok(Preview {
        generation,
        as_enforced,
        groups,
        more_groups,
        jobs_read: jobs.len(),
        jobs_capped: jobs.len() >= JOB_SCAN,
        lost,
        maybe_lost,
        more_lost,
        affected,
        affected_unreported: unreported,
        observed_capped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::DEFAULT_RULE;
    use vk_hub_proto::egress::HubPhase;

    fn rule(name: &str, mode: RuleMode) -> EgressRuleRow {
        EgressRuleRow {
            name: name.into(),
            subject: (name != DEFAULT_RULE).then(|| crate::subject::Subject::parse("*").unwrap()),
            run: HubPhase::Unrestricted,
            build: HubPhase::Unrestricted,
            mode,
            version: 1,
            generation: 1,
            created_at: 0,
            created_by: "t".into(),
            updated_at: 0,
            updated_by: "t".into(),
        }
    }

    /// A rule added or left in dry-run is compared as enforced; one moved from enforced to
    /// dry-run as it is, since that changes what is enforced.
    #[test]
    fn a_dry_run_rule_is_compared_as_enforced_unless_it_was_enforced() {
        let rules = vec![
            rule(DEFAULT_RULE, RuleMode::Enforce),
            rule("a", RuleMode::Enforce),
        ];
        let (after, compared, as_enforced) =
            apply(&rules, &Edit::Put(Box::new(rule("b", RuleMode::DryRun))));
        assert!(as_enforced);
        assert_eq!(after.len(), 3);
        assert!(compared.iter().all(|r| r.mode == RuleMode::Enforce));
        let (_, compared, as_enforced) =
            apply(&rules, &Edit::Put(Box::new(rule("a", RuleMode::DryRun))));
        assert!(!as_enforced);
        assert!(
            compared
                .iter()
                .any(|r| r.name == "a" && r.mode == RuleMode::DryRun)
        );
        let (after, compared, as_enforced) = apply(&rules, &Edit::Remove("a".into()));
        assert!(!as_enforced);
        assert_eq!((after.len(), compared.len()), (1, 1));
    }
}
