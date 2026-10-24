//! What a change to the hub's egress rules would do, before it is saved (`docs/fleet-design.md`,
//! *Rules on the page*): the recent jobs whose layer it changes or that the rule selects, each
//! group of them with its layer before and after, both resolved with [`resolve_egress`] from
//! their records' claims.
//!
//! A dry-run rule blocks nothing: a change that leaves one in dry-run, or adds one, is compared
//! as it would be enforced, which is what its jobs' reports then show as would-block.
//!
//! Every read is bounded: the latest [`JOB_SCAN`] jobs; what is shown is bounded apart, and
//! says when it was cut.

use std::collections::HashMap;

use anyhow::Result;
use vk_hub_proto::egress::HubEgress;

use super::rules::claims_of;
use crate::server::Hub;
use crate::store::{EgressRuleRow, RuleMode, resolve_egress};
use crate::subject::JobClaims;

/// The latest jobs of the history a preview reads.
pub const JOB_SCAN: usize = 1000;
/// The most groups of jobs a preview lists.
pub const MAX_GROUPS: usize = 200;

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
    let mut groups: Vec<Group> = Vec::new();
    let mut at: HashMap<ClaimsKey, usize> = HashMap::new();
    for (id, j) in &jobs {
        let claims = claims_of(j);
        let (before, after) = layers.of(claims.as_ref()).clone();
        if before == after && !names(&before) && !names(&after) {
            continue;
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

    Ok(Preview {
        generation,
        as_enforced,
        groups,
        more_groups,
        jobs_read: jobs.len(),
        jobs_capped: jobs.len() >= JOB_SCAN,
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
