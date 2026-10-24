//! Hub rules proposed from the evidence (`docs/fleet-design.md`, *Egress page*, *Actions follow
//! the deciding layer*): a destination a hub rule refused, on a Blocked row, a job's Network
//! access or Observed traffic, allowed for its project in the phase it was refused in, by an
//! existing rule that applies to the project or a new rule for exactly that project.
//!
//! Only a denial its nodes recorded as decided by a hub rule seeds a proposal: a node's cap, a
//! job's or a service's narrowing is not the hub's to widen, and a destination that is neither a
//! domain nor an IPv4 address and port never becomes an entry. The entry is the destination as
//! reported — `deb.debian.org`, never `debian.org`; `10.0.0.1/32:443` — and nothing is saved but
//! through the editor's Preview → Save.

use std::collections::{BTreeMap, BTreeSet};

use vk_hub_proto::egress::{
    EgressDestination, EgressDimension, EgressLayer, EgressOutcome, EgressPhase, EgressProtocol,
    HubPhase, check_allow_name,
};

use super::blocked::{Finding, Subject, View};
use super::matching::{Dest, Verdict, dns_refused, verdict};
use crate::store::{BlockedRow, DEFAULT_RULE, EgressRuleRow, JobRow, RuleMode, resolve_egress};
use crate::subject::{JobClaims, Projects};

/// The allow entry a destination makes, exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub dimension: EgressDimension,
    pub text: String,
}

/// The entry that allows exactly `d`, as reported: a domain as it is, an address as `/32` on its
/// port. `None` for anything else, which never seeds an entry.
pub fn entry(d: &EgressDestination) -> Option<Entry> {
    match d {
        EgressDestination::Domain { name }
            if vk_hub_proto::egress::is_domain(name) && check_allow_name(name).is_ok() =>
        {
            Some(Entry {
                dimension: EgressDimension::Name,
                text: name.clone(),
            })
        }
        // Port 0 names no port an entry could keep: `/32` alone would allow every port.
        EgressDestination::Address { ip, port } if *port != 0 => Some(Entry {
            dimension: EgressDimension::Ip,
            text: format!("{ip}/32:{port}"),
        }),
        _ => None,
    }
}

/// Why no hub rule is proposed for a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoProposal {
    /// A declaration issue: the job's configuration, not a destination.
    Refusal,
    /// Neither a domain nor an address.
    NotAllowable,
    /// An address on DNS's port, which every layer that restricts refuses whatever it lists.
    Dns,
    /// A node's cap refused it, which no hub rule widens.
    NodeCap,
    /// The job's or a service's own narrowing refused it.
    Narrowing,
    /// The layer is unknown, or no job kept recorded it.
    Unknown,
    /// The rules saved now already allow it.
    Allowed,
}

impl NoProposal {
    /// Why, in words, for the page.
    pub fn text(self) -> &'static str {
        match self {
            NoProposal::Refusal => "a declaration is the job's to correct, in its CI configuration",
            NoProposal::NotAllowable => "it is not a name or an address: nothing to allow",
            NoProposal::Dns => {
                "it is a lookup sent to a DNS server, which no rule allows: jobs look names up \
                 through their node's resolver"
            }
            NoProposal::NodeCap => {
                "a node's cap refused it, and a hub rule cannot override a node's cap"
            }
            NoProposal::Narrowing => {
                "the job's own narrowing refused it: change the job's CI configuration"
            }
            NoProposal::Unknown => "no job kept says a hub rule refused it",
            NoProposal::Allowed => "the rules saved now already allow it",
        }
    }
}

/// What a proposal is made from: a destination a hub rule refused a subject's jobs, and those
/// jobs' claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    pub subject: Subject,
    /// [`View::Blocked`], or [`View::WouldBlock`] for a dry-run rule's.
    pub view: View,
    pub protocol: EgressProtocol,
    pub destination: EgressDestination,
    pub entry: Entry,
    /// The phases a hub rule refused it in, run before build.
    pub phases: Vec<EgressPhase>,
    /// For a would-block, the dry-run rules that would have refused it.
    pub dry_run: BTreeSet<String>,
    /// The claims of the jobs it comes from, the latest first; `None` for a job of a key bound
    /// to no GitLab instance.
    pub claims: Vec<Option<JobClaims>>,
    /// The project path its latest job named.
    pub project: Option<String>,
}

impl Seed {
    /// The claims a save is checked against: its latest job's.
    pub fn latest(&self) -> Option<&JobClaims> {
        self.claims.first().and_then(Option::as_ref)
    }
}

/// The phases of a run before a build, as [`super::blocked::phase_key`] names them.
pub fn phase_key(p: EgressPhase) -> Option<&'static str> {
    match p {
        EgressPhase::Run => Some("run"),
        EgressPhase::Build => Some("build"),
        EgressPhase::Other => None,
    }
}

/// The phase named `key`.
pub fn phase_of_key(key: &str) -> Option<EgressPhase> {
    match key {
        "run" => Some(EgressPhase::Run),
        "build" => Some(EgressPhase::Build),
        _ => None,
    }
}

/// The proposal row `row` seeds from its latest jobs kept, `jobs`, the latest first: the
/// entries of its destination they recorded as decided by a hub rule.
pub fn of_row(row: &BlockedRow, jobs: &[&JobRow]) -> Result<Seed, NoProposal> {
    let Finding::Denial {
        view,
        protocol,
        destination,
    } = &row.finding
    else {
        return Err(NoProposal::Refusal);
    };
    let Some(entry) = entry(destination) else {
        return Err(NoProposal::NotAllowable);
    };
    if Dest::of(destination).is_some_and(|d| dns_refused(&d)) {
        return Err(NoProposal::Dns);
    }
    if *protocol == EgressProtocol::Other {
        return Err(NoProposal::NotAllowable);
    }
    let outcome = match view {
        View::Blocked => EgressOutcome::Blocked,
        View::WouldBlock => EgressOutcome::WouldBlock,
        View::Refused => return Err(NoProposal::Refusal),
    };
    let mut phases = BTreeSet::new();
    let mut dry_run = BTreeSet::new();
    let mut claims = Vec::new();
    let mut layers = std::collections::HashSet::new();
    for j in jobs {
        let entries = super::report(j)
            .map(|r| r.entries.as_slice())
            .unwrap_or_default();
        let mut used = false;
        for e in entries.iter().filter(|e| {
            e.outcome == outcome && e.protocol == *protocol && e.destination == *destination
        }) {
            layers.insert(e.layer.unwrap_or(EgressLayer::Unknown));
            if e.layer != Some(EgressLayer::HubRule) {
                continue;
            }
            let Some(key) = phase_key(e.phase) else {
                continue;
            };
            if *view == View::WouldBlock {
                // A would-block names the dry-run rule that would have refused it.
                let Some(rule) = &e.rule else {
                    continue;
                };
                dry_run.insert(rule.clone());
            }
            phases.insert(key);
            used = true;
        }
        if used {
            claims.push(super::rules::claims_of(j));
        }
    }
    if phases.is_empty() {
        return Err(if layers.contains(&EgressLayer::NodeCap) {
            NoProposal::NodeCap
        } else if layers.contains(&EgressLayer::Job) || layers.contains(&EgressLayer::Service) {
            NoProposal::Narrowing
        } else {
            NoProposal::Unknown
        });
    }
    let project = jobs
        .iter()
        .find(|j| j.project.is_some())
        .and_then(|j| j.project.clone())
        .or_else(|| row.project.clone());
    Ok(Seed {
        subject: row.subject.clone(),
        view: *view,
        protocol: *protocol,
        destination: destination.clone(),
        entry,
        phases: ["run", "build"]
            .into_iter()
            .filter(|k| phases.contains(k))
            .filter_map(phase_of_key)
            .collect(),
        dry_run,
        claims,
        project,
    })
}

/// The proposal a contact of Observed traffic seeds: one `subject`'s jobs of `claims` reached
/// `destination` in `phase`, and the rules saved now leave it outside for at least one of them.
pub fn of_contact(
    subject: &Subject,
    project: Option<&str>,
    protocol: EgressProtocol,
    destination: &EgressDestination,
    phase: EgressPhase,
    claims: Vec<Option<JobClaims>>,
    rules: &[EgressRuleRow],
) -> Result<Seed, NoProposal> {
    let Some(entry) = entry(destination) else {
        return Err(NoProposal::NotAllowable);
    };
    if Dest::of(destination).is_some_and(|d| dns_refused(&d)) {
        return Err(NoProposal::Dns);
    }
    if protocol == EgressProtocol::Other || phase_key(phase).is_none() {
        return Err(NoProposal::NotAllowable);
    }
    let dest = Dest::of(destination).ok_or(NoProposal::NotAllowable)?;
    if claims
        .iter()
        .all(|c| allows(View::Blocked, "", rules, c.as_ref(), phase, &dest))
    {
        return Err(NoProposal::Allowed);
    }
    Ok(Seed {
        subject: subject.clone(),
        view: View::Blocked,
        protocol,
        destination: destination.clone(),
        entry,
        phases: vec![phase],
        dry_run: BTreeSet::new(),
        claims,
        project: project.map(str::to_string),
    })
}

/// Whether `rules` allow `dest` in `phase` to the job claiming `claims`: for
/// [`View::WouldBlock`] the dry-run rule `rule` were it enforced, as long as it still applies in
/// dry-run, since it refuses on its own whatever the enforced layer allows; else, as for a block,
/// the enforced layer.
pub fn allows(
    view: View,
    rule: &str,
    rules: &[EgressRuleRow],
    claims: Option<&JobClaims>,
    phase: EgressPhase,
    dest: &Dest,
) -> bool {
    let layer = resolve_egress(rules, claims);
    let trial = layer
        .dry_run
        .iter()
        .find(|d| view == View::WouldBlock && d.rule == rule);
    let p = match (trial, phase) {
        (Some(d), EgressPhase::Run) => Some(&d.run),
        (Some(d), EgressPhase::Build) => Some(&d.build),
        (Some(_), EgressPhase::Other) => None,
        (None, _) => layer.phase(phase),
    };
    p.is_some_and(|p| verdict(p, dest).allows())
}

/// How an existing rule stands for a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Adding the entry to its phase allows it there.
    Adds,
    /// Its phase already allows it: another rule or layer refuses it.
    AlreadyAllows,
    /// Its phase is unrestricted: nothing to add.
    Unrestricted,
}

/// An existing rule a proposal may extend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target<'a> {
    pub rule: &'a EgressRuleRow,
    /// Of the seed's jobs, how many it applies to now.
    pub applies: usize,
    pub standing: Standing,
}

/// The rules that apply to the seed's jobs now and may take its entry in `phase`: for a block,
/// the enforced rules, the Fallback where it applies; for a would-block, the dry-run rules that
/// would have refused it. In name order.
pub fn targets<'a>(seed: &Seed, rules: &'a [EgressRuleRow], phase: EgressPhase) -> Vec<Target<'a>> {
    let mut applies: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &seed.claims {
        let layer = resolve_egress(rules, c.as_ref());
        let names: Vec<String> = match seed.view {
            View::WouldBlock => layer
                .dry_run
                .into_iter()
                .map(|d| d.rule)
                .filter(|r| seed.dry_run.contains(r))
                .collect(),
            _ => layer.rules,
        };
        for n in names {
            if let Some(r) = rules.iter().find(|r| r.name == n) {
                *applies.entry(r.name.as_str()).or_default() += 1;
            }
        }
    }
    let Some(dest) = Dest::of(&seed.destination) else {
        return Vec::new();
    };
    applies
        .into_iter()
        .filter_map(|(name, applies)| {
            let rule = rules.iter().find(|r| r.name == name)?;
            let p = rule_phase(rule, phase)?;
            let standing = match verdict(p, &dest) {
                Verdict::Unrestricted => Standing::Unrestricted,
                Verdict::Allowed(_) => Standing::AlreadyAllows,
                _ => Standing::Adds,
            };
            Some(Target {
                rule,
                applies,
                standing,
            })
        })
        .collect()
}

/// Rule `r`'s `phase`.
pub fn rule_phase(r: &EgressRuleRow, phase: EgressPhase) -> Option<&HubPhase> {
    match phase {
        EgressPhase::Run => Some(&r.run),
        EgressPhase::Build => Some(&r.build),
        EgressPhase::Other => None,
    }
}

/// `p` with `e` listed: added to its dimension, once; a phase allowing none now allows it alone.
/// An unrestricted phase stays so.
pub fn with_entry(p: &HubPhase, e: &Entry) -> HubPhase {
    match p {
        HubPhase::Allow { names, ips } => {
            let (mut names, mut ips) = (names.clone(), ips.clone());
            let list = match e.dimension {
                EgressDimension::Ip => &mut ips,
                _ => &mut names,
            };
            if !list.contains(&e.text) {
                list.push(e.text.clone());
            }
            HubPhase::Allow { names, ips }
        }
        other => other.clone(),
    }
}

/// How a new rule for the project is selected: by its ID, or its path exactly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum By {
    #[default]
    Id,
    Path,
}

/// A new rule's subject, exactly the seed's project: `None` for a key bound to no GitLab
/// instance, or by a path that is not one exactly — a glob's `*` would select others.
pub fn new_subject(seed: &Seed, by: By) -> Option<crate::subject::Subject> {
    let Subject::Gitlab {
        instance,
        project_id,
    } = &seed.subject
    else {
        return None;
    };
    let projects = match by {
        By::Id => Projects::Id(*project_id),
        By::Path => {
            let path = seed.project.as_deref().filter(|p| exact_path(p))?;
            Projects::Path(path.to_string())
        }
    };
    Some(crate::subject::Subject {
        projects,
        gitlab: Some(instance.clone()),
        ..crate::subject::Subject::default()
    })
}

/// Whether `path` selects itself alone as a rule's project pattern.
pub fn exact_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('*')
        && !path.contains(|c: char| c.is_whitespace() || c == ',')
}

/// What a new rule starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    /// The enforced Fallback's lists, the entry added: where the rule replaces the Fallback,
    /// only the entry changes.
    Fallback,
    /// The entry alone, the other phase allowing none: rules add up, so beside an enforced rule
    /// only the entry changes.
    Entry,
}

/// The enforced Fallback of `rules`.
pub fn enforced_fallback(rules: &[EgressRuleRow]) -> Option<&EgressRuleRow> {
    rules
        .iter()
        .find(|r| r.name == DEFAULT_RULE && r.mode == RuleMode::Enforce)
}

/// Whether the seed's jobs mix those the Fallback alone applies to with those an enforced rule
/// selects, which neither base keeps unchanged. A new rule starts from [`Base::Entry`] unless
/// asked: the Fallback's lists, copied, would reach every job of the project the rule selects,
/// whatever its ref and protection, beside any enforced rule's.
pub fn mixed(seed: &Seed, rules: &[EgressRuleRow]) -> bool {
    let fallback_only = |c: &Option<JobClaims>| {
        resolve_egress(rules, c.as_ref()).rules == [DEFAULT_RULE.to_string()]
    };
    let alone = seed.claims.iter().filter(|c| fallback_only(c)).count();
    alone > 0 && alone < seed.claims.len()
}

/// A new rule's phases from `base`, its entry in `phase`.
pub fn new_phases(
    seed: &Seed,
    rules: &[EgressRuleRow],
    phase: EgressPhase,
    base: Base,
) -> (HubPhase, HubPhase) {
    let none = HubPhase::Allow {
        names: Vec::new(),
        ips: Vec::new(),
    };
    let (run, build) = match (base, enforced_fallback(rules)) {
        (Base::Fallback, Some(f)) => (f.run.clone(), f.build.clone()),
        _ => (none.clone(), none),
    };
    match phase {
        EgressPhase::Build => (run, with_entry(&build, &seed.entry)),
        _ => (with_entry(&run, &seed.entry), build),
    }
}

/// A name for a new rule: the project path's last part, as a rule's name may spell it, taken by
/// no rule of `rules`.
pub fn new_name(seed: &Seed, rules: &[EgressRuleRow]) -> String {
    let stem: String = seed
        .project
        .as_deref()
        .and_then(|p| p.rsplit('/').next())
        .unwrap_or_default()
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '-',
        })
        .take(48)
        .collect();
    let stem = match (stem.trim_matches('-'), &seed.subject) {
        ("", Subject::Gitlab { project_id, .. }) => format!("project-{project_id}"),
        ("", _) => "project".to_string(),
        (s, _) => s.to_string(),
    };
    let taken = |n: &str| n == DEFAULT_RULE || rules.iter().any(|r| r.name == n);
    if !taken(&stem) {
        return stem;
    }
    (2..)
        .map(|i| format!("{stem}-{i}"))
        .find(|n| !taken(n))
        .unwrap_or(stem)
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::EgressReport;

    use super::*;
    use crate::egress::blocked::shares;
    use crate::egress::testing::{entry as report_entry, job};
    use crate::store::EgressRulesApplied;

    fn allow(names: &[&str], ips: &[&str]) -> HubPhase {
        HubPhase::Allow {
            names: names.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn rule(name: &str, subject: Option<&str>, run: HubPhase, build: HubPhase) -> EgressRuleRow {
        EgressRuleRow {
            name: name.into(),
            subject: subject.map(|s| crate::subject::Subject::parse(s).unwrap()),
            run,
            build,
            mode: RuleMode::Enforce,
            version: 1,
            generation: 1,
            created_at: 0,
            created_by: "t".into(),
            updated_at: 0,
            updated_by: "t".into(),
        }
    }

    fn denied(outcome: EgressOutcome, layer: EgressLayer, dest: &str) -> JobRow {
        let mut e = report_entry(
            outcome,
            EgressProtocol::Dns,
            EgressDestination::domain(dest),
            Some(layer),
        );
        e.phase = EgressPhase::Build;
        if outcome == EgressOutcome::WouldBlock {
            e.rule = Some("dry".into());
        }
        let mut j = job(
            1,
            EgressReport {
                entries: vec![e],
                ..EgressReport::default()
            },
        );
        (j.gitlab, j.project_id, j.protected) = (Some("gl".into()), Some(42), Some(true));
        j.egress_rules = Some(EgressRulesApplied {
            rules: vec!["wab".into()],
            dry_run: vec![],
            generation: 3,
        });
        j
    }

    fn row_of(j: &JobRow) -> BlockedRow {
        let share = shares(j).into_values().next().unwrap();
        BlockedRow {
            subject: share.subject,
            finding: share.finding,
            project: j.project.clone(),
            key_name: "gitlab".into(),
            jobs: 1,
            attempts: 1,
            latest_at: 1,
            layers: BTreeMap::new(),
            phases: BTreeMap::new(),
            generation: 1,
            acknowledged: None,
            allows: Vec::new(),
        }
    }

    /// A hub rule's denial seeds the exact destination in the phases it was refused in; a
    /// node's cap, a narrowing or an unknown layer seeds nothing, nor does a malformed name.
    #[test]
    fn only_a_hub_rule_s_denial_of_a_name_or_address_seeds_a_proposal() {
        let j = denied(
            EgressOutcome::Blocked,
            EgressLayer::HubRule,
            "deb.debian.org",
        );
        let seed = of_row(&row_of(&j), &[&j]).unwrap();
        assert_eq!(seed.entry.text, "deb.debian.org");
        assert_eq!(seed.phases, vec![EgressPhase::Build]);
        assert_eq!(seed.latest().unwrap().project_id, 42);
        for (layer, why) in [
            (EgressLayer::NodeCap, NoProposal::NodeCap),
            (EgressLayer::Job, NoProposal::Narrowing),
            (EgressLayer::Service, NoProposal::Narrowing),
            (EgressLayer::Unknown, NoProposal::Unknown),
        ] {
            let j = denied(EgressOutcome::Blocked, layer, "deb.debian.org");
            assert_eq!(of_row(&row_of(&j), &[&j]), Err(why));
        }
        let j = denied(EgressOutcome::Blocked, EgressLayer::HubRule, "<b>x");
        assert_eq!(of_row(&row_of(&j), &[&j]), Err(NoProposal::NotAllowable));
        // A lookup sent to a DNS server: no entry would allow it.
        let mut j = denied(EgressOutcome::Blocked, EgressLayer::HubRule, "x.example");
        let report = j.result.as_mut().and_then(|r| r.egress.as_mut()).unwrap();
        report.entries[0].protocol = EgressProtocol::Udp;
        report.entries[0].destination = EgressDestination::Address {
            ip: "1.1.1.1".parse().unwrap(),
            port: 53,
        };
        assert_eq!(of_row(&row_of(&j), &[&j]), Err(NoProposal::Dns));
        // A would-block names its dry-run rule.
        let j = denied(EgressOutcome::WouldBlock, EgressLayer::HubRule, "x.example");
        let seed = of_row(&row_of(&j), &[&j]).unwrap();
        assert_eq!(seed.dry_run, BTreeSet::from(["dry".to_string()]));
        // An address is allowed exactly, on its port.
        assert_eq!(
            entry(&EgressDestination::address("10.0.0.1:443"))
                .unwrap()
                .text,
            "10.0.0.1/32:443"
        );
        assert_eq!(entry(&EgressDestination::Other), None);
        // Port 0 names no port an entry could keep.
        assert_eq!(entry(&EgressDestination::address("10.0.0.1:0")), None);
    }

    /// The rules that apply to the jobs are offered, standing as they do for the entry; a new
    /// rule for exactly the project starts from the Fallback only where it alone applies.
    #[test]
    fn a_proposal_targets_the_rules_that_apply_or_a_new_rule_for_the_project() {
        let j = denied(
            EgressOutcome::Blocked,
            EgressLayer::HubRule,
            "deb.debian.org",
        );
        let mut seed = of_row(&row_of(&j), &[&j]).unwrap();
        seed.project = Some("acme/web".into());
        let rules = vec![
            rule(
                DEFAULT_RULE,
                None,
                HubPhase::Unrestricted,
                allow(&["crates.io"], &[]),
            ),
            rule(
                "wab",
                Some("gitlab gl, project-id 42, protected"),
                allow(&[], &[]),
                allow(&["pypi.org"], &[]),
            ),
            rule(
                "other",
                Some("gitlab gl, project-id 7"),
                allow(&[], &[]),
                allow(&[], &[]),
            ),
        ];
        let t = targets(&seed, &rules, EgressPhase::Build);
        assert_eq!(t.len(), 1);
        assert_eq!(
            (t[0].rule.name.as_str(), t[0].standing),
            ("wab", Standing::Adds)
        );
        assert_eq!(
            with_entry(&t[0].rule.build, &seed.entry),
            allow(&["pypi.org", "deb.debian.org"], &[])
        );
        assert!(!mixed(&seed, &rules));
        assert_eq!(
            new_phases(&seed, &rules, EgressPhase::Build, Base::Entry),
            (allow(&[], &[]), allow(&["deb.debian.org"], &[]))
        );
        // Unprotected, the Fallback alone applies: a new rule keeps what it allows.
        seed.claims = vec![seed.claims[0].clone().map(|mut c| {
            c.protected = false;
            c
        })];
        assert_eq!(
            targets(&seed, &rules, EgressPhase::Build)[0].rule.name,
            DEFAULT_RULE
        );
        assert!(!mixed(&seed, &rules));
        assert_eq!(
            new_phases(&seed, &rules, EgressPhase::Build, Base::Fallback),
            (
                HubPhase::Unrestricted,
                allow(&["crates.io", "deb.debian.org"], &[])
            )
        );
        assert_eq!(
            new_subject(&seed, By::Path).unwrap().to_string(),
            "gitlab gl, projects acme/web"
        );
        assert_eq!(
            new_subject(&seed, By::Id).unwrap().to_string(),
            "gitlab gl, project-id 42"
        );
        seed.project = Some("acme/*".into());
        assert_eq!(new_subject(&seed, By::Path), None);
        assert_eq!(new_name(&seed, &rules), "project-42");
        seed.project = Some("acme/wab".into());
        assert_eq!(new_name(&seed, &rules), "wab-2");
        // Saved, the Fallback now allows it.
        let mut after = rules.clone();
        after[0].build = with_entry(&after[0].build, &seed.entry);
        let dest = Dest::Name("deb.debian.org".into());
        assert!(!allows(
            View::Blocked,
            "",
            &rules,
            seed.latest(),
            EgressPhase::Build,
            &dest
        ));
        assert!(allows(
            View::Blocked,
            "",
            &after,
            seed.latest(),
            EgressPhase::Build,
            &dest
        ));
    }

    /// A would-block stands while its dry-run rule refuses it, whatever the enforced rules
    /// allow; once that rule is enforced, the enforced layer decides.
    #[test]
    fn a_would_block_is_allowed_by_its_dry_run_rule_alone() {
        let claims = JobClaims {
            gitlab: "gl".into(),
            project_id: 42,
            project_path: "acme/web".into(),
            git_ref: "main".into(),
            protected: true,
            pipeline_id: 0,
        };
        let dest = Dest::Name("x.example".into());
        let mut trial = rule(
            "dry",
            Some("gitlab gl, project-id 42"),
            allow(&["other.example"], &[]),
            HubPhase::Unrestricted,
        );
        trial.mode = RuleMode::DryRun;
        let fallback = rule(
            DEFAULT_RULE,
            None,
            HubPhase::Unrestricted,
            HubPhase::Unrestricted,
        );
        let rules = vec![fallback, trial];
        let run = EgressPhase::Run;
        let would = |rules: &[EgressRuleRow]| {
            allows(View::WouldBlock, "dry", rules, Some(&claims), run, &dest)
        };
        assert!(allows(View::Blocked, "", &rules, Some(&claims), run, &dest));
        assert!(!would(&rules));
        let mut widened = rules.clone();
        widened[1].run = with_entry(
            &widened[1].run,
            &entry(&EgressDestination::domain("x.example")).unwrap(),
        );
        assert!(would(&widened));
        let mut enforced = rules.clone();
        enforced[1].mode = RuleMode::Enforce;
        assert!(!would(&enforced));
    }
}
