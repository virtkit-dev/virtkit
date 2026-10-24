//! The hub's egress rules (`docs/fleet-design.md`, *Job egress from the hub*): per rule, the
//! jobs it selects, by project and ref as a registry namespace's grant does, and what each
//! phase, run and build, may reach under it; enforced, or in dry-run. The reserved rule
//! [`DEFAULT_RULE`], the Fallback, selects no job by itself: it applies to a job no other
//! enforced rule selects. A placed job's layer is resolved from them ([`resolve_egress`]).
//!
//! Every change is audited, and moves the rules' generation on, so that what a job was resolved
//! under can be told apart from what holds now. A rule's entries are held to the checks a
//! node's switch makes of its own `[egress]` lists: the hub never stores what a node would
//! refuse.

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::egress::{
    DryRunRule, HubEgress, HubPhase, MAX_HUB_ENTRIES, check_allow_name, parse_allow_ip,
    valid_rule_name,
};

use super::{Db, append_audit, decode, encode};
use crate::subject::{JobClaims, Projects, Subject};

/// Key: a rule's name. Value: JSON [`EgressRuleRow`].
pub(super) const EGRESS_RULES: TableDefinition<&str, &[u8]> = TableDefinition::new("egress_rules");
/// Key: [`GENERATION`]. Value: the rules' generation, moved on by every change.
pub(super) const EGRESS_RULES_META: TableDefinition<&str, u64> =
    TableDefinition::new("egress_rules_meta");
const GENERATION: &str = "generation";

/// The reserved rule a job gets when no other enforced rule selects it: the Fallback.
pub const DEFAULT_RULE: &str = "default";

/// The most rules the hub holds. A job's layer names at most
/// [`vk_hub_proto::egress::MAX_HUB_RULES`] of them: one selected by more fails to place.
pub const MAX_EGRESS_RULES: usize = 128;

/// The longest entry a rule lists, in bytes: a domain name's longest.
const MAX_ENTRY: usize = 253;

/// Whether a rule decides what jobs reach, or only reports what it would refuse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleMode {
    #[default]
    Enforce,
    DryRun,
}

impl RuleMode {
    pub fn name(self) -> &'static str {
        match self {
            RuleMode::Enforce => "enforce",
            RuleMode::DryRun => "dry-run",
        }
    }

    pub fn parse(s: &str) -> Option<RuleMode> {
        match s {
            "enforce" => Some(RuleMode::Enforce),
            "dry-run" => Some(RuleMode::DryRun),
            _ => None,
        }
    }
}

/// An egress rule as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRuleRow {
    pub name: String,
    /// The jobs it selects; `None` for [`DEFAULT_RULE`] alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    pub run: HubPhase,
    pub build: HubPhase,
    pub mode: RuleMode,
    /// 1 when added, moved on by each change to it.
    pub version: u64,
    /// The rules' generation its latest change moved them to.
    pub generation: u64,
    pub created_at: u64,
    pub created_by: String,
    pub updated_at: u64,
    pub updated_by: String,
}

/// A change to a rule: what is `None` stays as it is. A new rule names its subject, unless it
/// is [`DEFAULT_RULE`], and both its phases; its mode is dry-run unless given, but the
/// Fallback's must be given.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleChange {
    pub name: String,
    #[serde(default)]
    pub subject: Option<Subject>,
    #[serde(default)]
    pub run: Option<HubPhase>,
    #[serde(default)]
    pub build: Option<HubPhase>,
    #[serde(default)]
    pub mode: Option<RuleMode>,
}

/// Why a change made against one generation of the rules was refused: they have changed since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RulesChanged;

impl std::fmt::Display for RulesChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the egress rules changed since this change was previewed")
    }
}

impl std::error::Error for RulesChanged {}

/// A phase as the CLI and the audit log say it: `unrestricted`, `none`, or its lists.
pub fn phase_text(p: &HubPhase) -> String {
    match p {
        HubPhase::Unrestricted => "unrestricted".to_string(),
        HubPhase::Allow { names, ips } if names.is_empty() && ips.is_empty() => "none".to_string(),
        HubPhase::Allow { names, ips } => {
            format!("names [{}], ips [{}]", names.join(", "), ips.join(", "))
        }
        HubPhase::Other => "a kind this hub does not know".to_string(),
    }
}

impl EgressRuleRow {
    /// The jobs it selects, in words.
    pub fn subject_text(&self) -> String {
        match &self.subject {
            Some(s) => s.to_string(),
            None => "jobs no other enforced rule selects".to_string(),
        }
    }

    /// Why this rule may not be stored, if it may not.
    pub fn check(&self) -> Result<(), String> {
        if !valid_rule_name(&self.name) {
            return Err(format!(
                "{:?} is not a rule's name: 1 to 64 letters, digits, '.', '_' and '-'",
                self.name
            ));
        }
        match (&self.subject, self.name == DEFAULT_RULE) {
            (Some(_), true) => {
                return Err(format!(
                    "{DEFAULT_RULE} applies to every job no other enforced rule selects: it \
                     takes no subject"
                ));
            }
            (None, false) => return Err(format!("rule {} needs a subject", self.name)),
            (Some(s), false) => check_subject(s)?,
            (None, true) => {}
        }
        check_phase(&self.run, "run")?;
        check_phase(&self.build, "build")
    }

    /// Whether it selects the job claiming `claims`: never [`DEFAULT_RULE`], and no rule a job
    /// with no claims, whose key is bound to no GitLab instance.
    fn selects(&self, claims: Option<&JobClaims>) -> bool {
        match (&self.subject, claims) {
            (Some(s), Some(c)) => s.matches(c),
            _ => false,
        }
    }
}

/// Why `s` may not select jobs for an egress rule, if it may not: `own project` and `own
/// pipeline` name nothing to an egress rule, and a ref by name says little unless protected.
fn check_subject(s: &Subject) -> Result<(), String> {
    if s.projects == Projects::Own || s.own_pipeline {
        return Err(
            "`own project` and `own pipeline` name a registry path's project; an egress rule \
             selects by `*`, `projects` or `project-id`"
                .to_string(),
        );
    }
    if s.git_ref.is_some() && s.protected != Some(true) {
        return Err(
            "a rule that selects by ref name must also say `protected`: anyone who can push \
             can name a branch anything"
                .to_string(),
        );
    }
    Ok(())
}

/// Why phase `p` may not be stored, if it may not: each entry is one a node's switch takes, at
/// most [`MAX_HUB_ENTRIES`] per list, none twice.
fn check_phase(p: &HubPhase, phase: &str) -> Result<(), String> {
    let HubPhase::Allow { names, ips } = p else {
        return match p {
            HubPhase::Other => Err(format!(
                "the {phase} phase is of a kind this hub does not know"
            )),
            _ => Ok(()),
        };
    };
    for (dimension, list) in [("names", names), ("ips", ips)] {
        if list.len() > MAX_HUB_ENTRIES {
            return Err(format!(
                "the {phase} phase lists {} {dimension}, past {MAX_HUB_ENTRIES}",
                list.len()
            ));
        }
        for (i, e) in list.iter().enumerate() {
            if e.len() > MAX_ENTRY {
                return Err(format!(
                    "the {phase} phase's {dimension} entry {:?} is longer than {MAX_ENTRY} bytes",
                    vk_hub_proto::display_safe(e)
                ));
            }
            if list.iter().take(i).any(|o| o == e) {
                return Err(format!("the {phase} phase lists {e:?} twice"));
            }
        }
    }
    for n in names {
        check_allow_name(n).map_err(|e| format!("the {phase} phase's names: {e}"))?;
    }
    for ip in ips {
        parse_allow_ip(ip).map_err(|e| format!("the {phase} phase's ips: {e}"))?;
    }
    Ok(())
}

/// The phases of `rules` added up: unrestricted if one is, else every list's entries, each
/// once, in order.
fn union<'a>(rules: impl IntoIterator<Item = &'a EgressRuleRow> + Clone) -> (HubPhase, HubPhase) {
    let add = |phase: &dyn Fn(&EgressRuleRow) -> &HubPhase| {
        let (mut names, mut ips): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        for r in rules.clone() {
            match phase(r) {
                HubPhase::Allow { names: n, ips: i } => {
                    for e in n {
                        if !names.contains(e) {
                            names.push(e.clone());
                        }
                    }
                    for e in i {
                        if !ips.contains(e) {
                            ips.push(e.clone());
                        }
                    }
                }
                // A kind this hub does not know is refused when stored; read as allowing
                // nothing, never as unrestricted.
                HubPhase::Other => {}
                HubPhase::Unrestricted => return HubPhase::Unrestricted,
            }
        }
        HubPhase::Allow { names, ips }
    };
    (add(&|r| &r.run), add(&|r| &r.build))
}

/// The hub's layer for the job claiming `claims`, from `rules`; `None` claims for a job whose
/// key is bound to no GitLab instance, which only [`DEFAULT_RULE`] applies to.
///
/// The enforced rules selecting the job add up, per phase and dimension; with none, the
/// Fallback applies if it is enforced, and otherwise the job may reach nothing. A dry-run rule
/// selects nothing: each one that would select the job comes as the layer the job would have
/// were it enforced, the enforced rules and it added up, the Fallback no longer applying. A
/// dry-run Fallback comes so when no enforced rule selects the job.
pub fn resolve_egress(rules: &[EgressRuleRow], claims: Option<&JobClaims>) -> HubEgress {
    let mut rules: Vec<&EgressRuleRow> = rules.iter().collect();
    rules.sort_by(|a, b| a.name.cmp(&b.name));
    let selecting = |mode: RuleMode| {
        rules
            .iter()
            .copied()
            .filter(move |r| r.mode == mode && r.selects(claims))
    };
    let enforced: Vec<&EgressRuleRow> = selecting(RuleMode::Enforce).collect();
    let fallback = rules.iter().copied().find(|r| r.name == DEFAULT_RULE);
    let none = || HubPhase::Allow {
        names: Vec::new(),
        ips: Vec::new(),
    };
    let (names, run, build) = match (enforced.is_empty(), fallback) {
        (false, _) => {
            let (run, build) = union(enforced.iter().copied());
            (
                enforced.iter().map(|r| r.name.clone()).collect(),
                run,
                build,
            )
        }
        (true, Some(f)) if f.mode == RuleMode::Enforce => {
            (vec![f.name.clone()], f.run.clone(), f.build.clone())
        }
        (true, _) => (Vec::new(), none(), none()),
    };
    let mut dry_run: Vec<DryRunRule> = selecting(RuleMode::DryRun)
        .map(|r| {
            let (run, build) = union(enforced.iter().copied().chain([r]));
            DryRunRule {
                rule: r.name.clone(),
                run,
                build,
            }
        })
        .collect();
    if let Some(f) = fallback.filter(|f| f.mode == RuleMode::DryRun && enforced.is_empty()) {
        dry_run.push(DryRunRule {
            rule: f.name.clone(),
            run: f.run.clone(),
            build: f.build.clone(),
        });
        dry_run.sort_by(|a, b| a.rule.cmp(&b.rule));
    }
    HubEgress {
        rules: names,
        run,
        build,
        dry_run,
    }
}

/// The layer of a job with no claims, a gitlab-runner job's: the Fallback's alone, from `txn`.
pub(super) fn fallback_in(txn: &redb::WriteTransaction) -> Result<HubEgress> {
    let fallback = txn
        .open_table(EGRESS_RULES)?
        .get(DEFAULT_RULE)?
        .map(|g| decode::<EgressRuleRow>(g.value()))
        .transpose()?;
    Ok(resolve_egress(fallback.as_slice(), None))
}

/// The rules' generation in `txn`: 0 before any change.
fn generation_in<T: redb::ReadableTable<&'static str, u64>>(table: &T) -> Result<u64> {
    Ok(table.get(GENERATION)?.map_or(0, |g| g.value()))
}

/// `rule` in words for the audit log.
fn rule_text(r: &EgressRuleRow) -> String {
    format!(
        "{} ({}; {}; version {}): run {}; build {}",
        r.name,
        r.subject_text(),
        r.mode.name(),
        r.version,
        phase_text(&r.run),
        phase_text(&r.build)
    )
}

impl Db {
    /// The egress rules, by name, and their generation.
    pub fn egress_rules(&self) -> Result<(u64, Vec<EgressRuleRow>)> {
        let txn = self.db.begin_read().context("starting a read")?;
        let generation = generation_in(&txn.open_table(EGRESS_RULES_META)?)?;
        let mut out = Vec::new();
        for entry in txn.open_table(EGRESS_RULES)?.iter()? {
            out.push(decode::<EgressRuleRow>(entry?.1.value())?);
        }
        Ok((generation, out))
    }

    /// Add rule `change.name`, or change the one of that name, audited as `actor`'s. Returns
    /// the rule as stored, whether it changed, and the nodes whose Fallback that changed.
    /// `exists` refuses a rule not stored yet.
    pub fn put_egress_rule(
        &self,
        change: &RuleChange,
        exists: bool,
        actor: &str,
        now: u64,
    ) -> Result<(EgressRuleRow, bool, Vec<String>)> {
        self.put_egress_rule_at(change, exists, None, actor, now)
    }

    /// [`Db::put_egress_rule`], refused with [`RulesChanged`] unless the rules are still at
    /// generation `expect`, when given: what a preview of the change was made against.
    pub fn put_egress_rule_at(
        &self,
        change: &RuleChange,
        exists: bool,
        expect: Option<u64>,
        actor: &str,
        now: u64,
    ) -> Result<(EgressRuleRow, bool, Vec<String>)> {
        let txn = self.db.begin_write().context("starting a write")?;
        let out = self.put_rule_in(&txn, change, exists, expect, actor, now)?;
        txn.commit().context("storing an egress rule")?;
        Ok(out)
    }

    /// [`Db::put_egress_rule_at`] from a proposal for a Blocked row: in the same write, the
    /// row's allow saved ([`super::egress`]) if the rules as changed allow its destination to
    /// the claims and in the phase `allow` names. Returns as it does, and whether the allow was
    /// saved.
    pub fn put_egress_rule_allowing(
        &self,
        change: &RuleChange,
        exists: bool,
        expect: u64,
        allow: &super::AllowRequest,
        actor: &str,
        now: u64,
    ) -> Result<(EgressRuleRow, bool, Vec<String>, bool)> {
        let txn = self.db.begin_write().context("starting a write")?;
        let (row, changed, steered) =
            self.put_rule_in(&txn, change, exists, Some(expect), actor, now)?;
        let generation = generation_in(&txn.open_table(EGRESS_RULES_META)?)?;
        let mut rules = Vec::new();
        for entry in txn.open_table(EGRESS_RULES)?.iter()? {
            rules.push(decode::<EgressRuleRow>(entry?.1.value())?);
        }
        let saved = super::egress::save_allow(&txn, allow, generation, &rules, actor, now)?;
        txn.commit().context("storing an egress rule")?;
        Ok((row, changed, steered, saved))
    }

    /// The write of [`Db::put_egress_rule_at`], in `txn`.
    fn put_rule_in(
        &self,
        txn: &redb::WriteTransaction,
        change: &RuleChange,
        exists: bool,
        expect: Option<u64>,
        actor: &str,
        now: u64,
    ) -> Result<(EgressRuleRow, bool, Vec<String>)> {
        let name = change.name.as_str();
        let (row, changed) = {
            let mut table = txn.open_table(EGRESS_RULES)?;
            let before = table
                .get(name)?
                .map(|g| decode::<EgressRuleRow>(g.value()))
                .transpose()?;
            let mut meta = txn.open_table(EGRESS_RULES_META)?;
            let now_at = generation_in(&meta)?;
            if expect.is_some_and(|g| g != now_at) {
                return Err(RulesChanged.into());
            }
            let generation = now_at.saturating_add(1);
            let row = match &before {
                Some(b) => EgressRuleRow {
                    subject: change.subject.clone().or_else(|| b.subject.clone()),
                    run: change.run.clone().unwrap_or_else(|| b.run.clone()),
                    build: change.build.clone().unwrap_or_else(|| b.build.clone()),
                    mode: change.mode.unwrap_or(b.mode),
                    version: b.version.saturating_add(1),
                    generation,
                    updated_at: now,
                    updated_by: actor.to_string(),
                    ..b.clone()
                },
                None if exists => bail!("there is no egress rule {name}"),
                None => {
                    if table.len()? >= MAX_EGRESS_RULES as u64 {
                        bail!("the hub holds {MAX_EGRESS_RULES} egress rules already");
                    }
                    let (Some(run), Some(build)) = (&change.run, &change.build) else {
                        bail!(
                            "a new rule chooses both its phases: unrestricted, none, or the \
                             destinations it allows"
                        );
                    };
                    let mode = match change.mode {
                        Some(m) => m,
                        None if name == DEFAULT_RULE => bail!(
                            "the Fallback's mode is chosen when it is added: enforce, or \
                             dry-run"
                        ),
                        None => RuleMode::DryRun,
                    };
                    EgressRuleRow {
                        name: name.to_string(),
                        subject: change.subject.clone(),
                        run: run.clone(),
                        build: build.clone(),
                        mode,
                        version: 1,
                        generation,
                        created_at: now,
                        created_by: actor.to_string(),
                        updated_at: now,
                        updated_by: actor.to_string(),
                    }
                }
            };
            if let Err(why) = row.check() {
                bail!("{why}");
            }
            let same = before.as_ref().is_some_and(|b| {
                (&b.subject, &b.run, &b.build, b.mode)
                    == (&row.subject, &row.run, &row.build, row.mode)
            });
            if same {
                (before.unwrap_or(row), false)
            } else {
                table.insert(name, encode(&row)?.as_slice())?;
                meta.insert(GENERATION, generation)?;
                (row, true)
            }
        };
        if changed {
            let event = match (row.version, exists) {
                (1, _) => format!("{actor} added egress rule {}", rule_text(&row)),
                (_, true)
                    if change.subject.is_none()
                        && change.run.is_none()
                        && change.build.is_none() =>
                {
                    format!(
                        "{actor} set egress rule {} to {} (version {})",
                        row.name,
                        row.mode.name(),
                        row.version
                    )
                }
                _ => format!("{actor} changed egress rule {}", rule_text(&row)),
            };
            append_audit(txn, None, actor, &event, now)?;
        }
        let steered = match changed && name == DEFAULT_RULE {
            true => self.steer_fallbacks_in(txn, now)?,
            false => Vec::new(),
        };
        Ok((row, changed, steered))
    }

    /// Remove rule `name`, audited as `actor`'s: whether there was one, and the nodes whose
    /// Fallback that changed.
    pub fn remove_egress_rule(
        &self,
        name: &str,
        actor: &str,
        now: u64,
    ) -> Result<(bool, Vec<String>)> {
        self.remove_egress_rule_at(name, None, actor, now)
    }

    /// [`Db::remove_egress_rule`], refused with [`RulesChanged`] unless the rules are still at
    /// generation `expect`, when given.
    pub fn remove_egress_rule_at(
        &self,
        name: &str,
        expect: Option<u64>,
        actor: &str,
        now: u64,
    ) -> Result<(bool, Vec<String>)> {
        let txn = self.db.begin_write().context("starting a write")?;
        if let Some(g) = expect
            && generation_in(&txn.open_table(EGRESS_RULES_META)?)? != g
        {
            return Err(RulesChanged.into());
        }
        let removed = txn.open_table(EGRESS_RULES)?.remove(name)?.is_some();
        let mut steered = Vec::new();
        if removed {
            {
                let mut meta = txn.open_table(EGRESS_RULES_META)?;
                let generation = generation_in(&meta)?.saturating_add(1);
                meta.insert(GENERATION, generation)?;
            }
            let event = format!("{actor} removed egress rule {name}");
            append_audit(&txn, None, actor, &event, now)?;
            if name == DEFAULT_RULE {
                steered = self.steer_fallbacks_in(&txn, now)?;
            }
        }
        txn.commit().context("removing an egress rule")?;
        Ok((removed, steered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(names: &[&str], ips: &[&str]) -> HubPhase {
        HubPhase::Allow {
            names: names.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn rule(name: &str, subject: Option<&str>, run: HubPhase, build: HubPhase) -> EgressRuleRow {
        EgressRuleRow {
            name: name.into(),
            subject: subject.map(|s| Subject::parse(s).unwrap()),
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

    fn dry(mut r: EgressRuleRow) -> EgressRuleRow {
        r.mode = RuleMode::DryRun;
        r
    }

    fn claims(path: &str, git_ref: &str, protected: bool) -> JobClaims {
        JobClaims {
            gitlab: "gl".into(),
            project_id: 42,
            project_path: path.into(),
            git_ref: git_ref.into(),
            protected,
            pipeline_id: 7,
        }
    }

    /// The spec's example rules.
    fn example() -> Vec<EgressRuleRow> {
        vec![
            rule(
                DEFAULT_RULE,
                None,
                allow(&[], &[]),
                allow(&["debian.org"], &[]),
            ),
            rule(
                "wab",
                Some("gitlab gl, projects wab/**, protected"),
                allow(&["corp.example.com"], &["10.10.140.49/32"]),
                allow(&["debian.org", "crates.io", "pypi.org"], &[]),
            ),
            rule(
                "wab-branches",
                Some("gitlab gl, projects wab/**, unprotected"),
                allow(&["corp.example.com"], &[]),
                allow(&["debian.org", "crates.io"], &[]),
            ),
            dry(rule(
                "wab-release",
                Some("gitlab gl, projects wab/**, ref release/*, protected"),
                allow(&["partner.example.net"], &[]),
                allow(&[], &[]),
            )),
        ]
    }

    #[test]
    fn enforced_rules_add_up_and_the_fallback_takes_the_rest() {
        let rules = example();
        let got = resolve_egress(&rules, Some(&claims("wab/core", "main", false)));
        assert_eq!(got.rules, vec!["wab-branches".to_string()]);
        assert_eq!(got.run, allow(&["corp.example.com"], &[]));
        assert!(got.dry_run.is_empty());
        // Another project, or a key bound to no instance: the Fallback alone.
        for c in [Some(claims("other/x", "main", true)), None] {
            let got = resolve_egress(&rules, c.as_ref());
            assert_eq!(got.rules, vec![DEFAULT_RULE.to_string()]);
            assert_eq!(got.build, allow(&["debian.org"], &[]));
            assert!(got.dry_run.is_empty());
        }
        // Two enforced rules add up, per phase and dimension; unrestricted absorbs.
        let mut more = rules.clone();
        more.push(rule(
            "all-protected",
            Some("protected"),
            allow(&["corp.example.com", "x.example"], &["10.0.0.0/8:443"]),
            HubPhase::Unrestricted,
        ));
        let got = resolve_egress(&more, Some(&claims("wab/core", "main", true)));
        assert_eq!(
            got.rules,
            vec!["all-protected".to_string(), "wab".to_string()]
        );
        assert_eq!(
            got.run,
            allow(
                &["corp.example.com", "x.example"],
                &["10.0.0.0/8:443", "10.10.140.49/32"]
            )
        );
        assert_eq!(got.build, HubPhase::Unrestricted);
        got.check().unwrap();
    }

    #[test]
    fn a_dry_run_rule_comes_as_the_layer_it_would_make() {
        let rules = example();
        let got = resolve_egress(&rules, Some(&claims("wab/core", "release/1", true)));
        assert_eq!(got.rules, vec!["wab".to_string()]);
        assert_eq!(
            got.dry_run,
            vec![DryRunRule {
                rule: "wab-release".into(),
                run: allow(
                    &["corp.example.com", "partner.example.net"],
                    &["10.10.140.49/32"]
                ),
                build: allow(&["debian.org", "crates.io", "pypi.org"], &[]),
            }]
        );
        // Without an enforced rule, the Fallback applies, and is dropped from the dry-run's.
        let only_dry: Vec<EgressRuleRow> =
            rules.iter().filter(|r| r.name != "wab").cloned().collect();
        let got = resolve_egress(&only_dry, Some(&claims("wab/core", "release/1", true)));
        assert_eq!(got.rules, vec![DEFAULT_RULE.to_string()]);
        assert_eq!(got.dry_run[0].run, allow(&["partner.example.net"], &[]));
        assert_eq!(got.dry_run[0].build, allow(&[], &[]));
    }

    #[test]
    fn with_no_enforced_fallback_a_job_no_rule_selects_reaches_nothing() {
        let none = allow(&[], &[]);
        let got = resolve_egress(&[], Some(&claims("a/b", "main", true)));
        assert_eq!((got.rules.len(), &got.run, &got.build), (0, &none, &none));
        let fallback = dry(rule(
            DEFAULT_RULE,
            None,
            HubPhase::Unrestricted,
            none.clone(),
        ));
        let got = resolve_egress(std::slice::from_ref(&fallback), None);
        assert!(got.rules.is_empty());
        assert_eq!(got.run, none);
        assert_eq!(got.dry_run.len(), 1);
        assert_eq!(got.dry_run[0].run, HubPhase::Unrestricted);
        // A dry-run Fallback does not apply where an enforced rule selects the job.
        let all = rule("all", Some("*"), none.clone(), none.clone());
        let got = resolve_egress(&[fallback, all], None);
        assert_eq!(got.dry_run.len(), 1, "no claims: `*` selects nothing");
        let got = resolve_egress(
            &[
                dry(rule(DEFAULT_RULE, None, none.clone(), none.clone())),
                rule("all", Some("*"), none.clone(), none),
            ],
            Some(&claims("a/b", "main", false)),
        );
        assert_eq!(got.rules, vec!["all".to_string()]);
        assert!(got.dry_run.is_empty());
    }

    #[test]
    fn a_rule_is_checked_as_a_node_checks_its_lists() {
        let ok = rule(
            "wab",
            Some("gitlab gl, projects wab/**, ref release/*, protected"),
            allow(&["corp.example.com"], &["10.0.0.0/8:443"]),
            HubPhase::Unrestricted,
        );
        ok.check().unwrap();
        let bad = |f: &dyn Fn(&mut EgressRuleRow)| {
            let mut r = ok.clone();
            f(&mut r);
            assert!(r.check().is_err(), "{r:?}");
        };
        bad(&|r| r.name = "a b".into());
        bad(&|r| r.subject = None);
        bad(&|r| r.subject = Some(Subject::parse("gitlab gl, projects x/**, ref main").unwrap()));
        bad(&|r| r.subject = Some(Subject::parse("own project").unwrap()));
        bad(&|r| r.run = allow(&["https://x"], &[]));
        bad(&|r| r.run = allow(&["x.example."], &[]));
        bad(&|r| r.run = allow(&[], &["::1"]));
        bad(&|r| r.run = allow(&[], &["10.0.0.0/33"]));
        bad(&|r| r.run = allow(&["a.b", "a.b"], &[]));
        bad(&|r| r.build = HubPhase::Other);
        bad(&|r| {
            r.run = HubPhase::Allow {
                names: (0..=MAX_HUB_ENTRIES).map(|i| format!("h{i}.x")).collect(),
                ips: Vec::new(),
            }
        });
        let mut fallback = rule(DEFAULT_RULE, None, HubPhase::Unrestricted, allow(&[], &[]));
        fallback.check().unwrap();
        fallback.subject = Some(Subject::parse("*").unwrap());
        assert!(fallback.check().is_err());
    }

    #[test]
    fn rules_are_stored_changed_and_removed_audited() {
        let db = Db::open_memory().unwrap();
        let change = |name: &str| RuleChange {
            name: name.into(),
            subject: Some(Subject::parse("gitlab gl, projects wab/**").unwrap()),
            run: Some(HubPhase::Unrestricted),
            build: Some(allow(&["debian.org"], &[])),
            mode: None,
        };
        // A new project rule starts in dry-run; the Fallback's mode is chosen.
        let (row, changed, _) = db
            .put_egress_rule(&change("wab"), false, "uid 1", 10)
            .unwrap();
        assert!(changed);
        assert_eq!(
            (row.mode, row.version, row.generation),
            (RuleMode::DryRun, 1, 1)
        );
        let fallback = RuleChange {
            subject: None,
            ..change(DEFAULT_RULE)
        };
        assert!(db.put_egress_rule(&fallback, false, "uid 1", 11).is_err());
        let fallback = RuleChange {
            mode: Some(RuleMode::Enforce),
            ..fallback
        };
        db.put_egress_rule(&fallback, false, "uid 1", 11).unwrap();
        // Unchanged: not stored again.
        let (_, changed, _) = db
            .put_egress_rule(&change("wab"), false, "uid 1", 12)
            .unwrap();
        assert!(!changed);
        // A change keeps what it does not name.
        let mode = RuleChange {
            name: "wab".into(),
            mode: Some(RuleMode::Enforce),
            ..RuleChange::default()
        };
        let (row, _, _) = db.put_egress_rule(&mode, true, "uid 1", 13).unwrap();
        assert_eq!(
            (row.mode, row.version, row.generation),
            (RuleMode::Enforce, 2, 3)
        );
        assert_eq!(row.run, HubPhase::Unrestricted);
        // A change made against an older generation is refused, and stores nothing.
        let stale = db.put_egress_rule_at(&mode, true, Some(2), "uid 1", 13);
        assert!(stale.unwrap_err().downcast_ref::<RulesChanged>().is_some());
        let missing = RuleChange {
            name: "nope".into(),
            ..mode
        };
        assert!(db.put_egress_rule(&missing, true, "uid 1", 13).is_err());
        let stale = db.remove_egress_rule_at("wab", Some(2), "uid 1", 14);
        assert!(stale.unwrap_err().downcast_ref::<RulesChanged>().is_some());
        assert!(
            db.remove_egress_rule_at("wab", Some(3), "uid 1", 14)
                .unwrap()
                .0
        );
        assert!(!db.remove_egress_rule("wab", "uid 1", 14).unwrap().0);
        let (generation, rules) = db.egress_rules().unwrap();
        assert_eq!(generation, 4);
        assert_eq!(rules.len(), 1);
        let found = db
            .audit_search(&crate::store::AuditFilter::default(), None, 10)
            .unwrap();
        let events: Vec<&str> = found.rows.iter().map(|(_, r)| r.event.as_str()).collect();
        assert_eq!(
            events,
            vec![
                "uid 1 removed egress rule wab",
                "uid 1 set egress rule wab to enforce (version 2)",
                "uid 1 added egress rule default (jobs no other enforced rule selects; enforce; \
                 version 1): run unrestricted; build names [debian.org], ips []",
                "uid 1 added egress rule wab (gitlab gl, projects wab/**; dry-run; version 1): \
                 run unrestricted; build names [debian.org], ips []",
            ]
        );
        assert!(
            found
                .rows
                .iter()
                .all(|(_, r)| super::super::audit::kind(&r.actor, &r.event)
                    == super::super::audit::AuditKind::People)
        );
    }
}
