//! An operator's change to the hub's egress rules from the Rules tab (`docs/fleet-design.md`,
//! *Rules on the page*): a rule added, changed or removed through Preview → Save, posted to
//! `/egress/rules`. The form chooses the jobs a rule selects as the namespaces page words them,
//! and each phase explicitly — *Unrestricted by this rule*, *Allow listed destinations*, *Allow
//! none* — never an absent list beside an empty one. A preview ([`crate::egress::preview`])
//! shows what the change would do, and carries the change, unchanged, to Save, with the rules'
//! generation it was made against: Save is refused once they have moved on. The store audits
//! each change as the session's principal, and steers nodes to a Fallback changed.
//!
//! Every entry is an operator's text, held to a node's checks before anything is stored; the
//! destinations a preview lists are guests', each through [`Html::node`].

use std::collections::BTreeSet;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::egress::{HubEgress, HubPhase, valid_rule_name};

use super::super::html::Html;
use super::super::{Auth, Body, Ui, blocking, field, fleet, html_response, message, pages};
use super::rules::{self as tab, applies_to, mode_badge, phase_summary, rule_href};
use super::{PATH as EGRESS, Tab, capital, see_other};
use crate::egress::blocked::{Instances, instances, project_label};
use crate::egress::preview::{self, Edit, Group, Lost, Preview};
use crate::egress::proposal;
use crate::egress::rules::{self as ops, Rules};
use crate::store::{
    AllowRequest, DEFAULT_RULE, EgressRuleRow, Role, RuleChange, RuleMode, RulesChanged,
};
use crate::subject::Subject;

/// Where the editor posts.
pub(in crate::ui) const ACTION_PATH: &str = "/egress/rules";

/// The largest form the editor posts: a rule's four lists at their longest, escaped.
pub(super) const MAX_RULE_FORM: usize = 512 * 1024;

/// A phase's choice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Choice {
    #[default]
    Unrestricted,
    Allow,
    None,
}

impl Choice {
    const ALL: [(Choice, &'static str, &'static str); 3] = [
        (
            Choice::Unrestricted,
            "unrestricted",
            "Unrestricted by this rule",
        ),
        (Choice::Allow, "allow", "Allow listed destinations"),
        (Choice::None, "none", "Allow none"),
    ];

    fn value(self) -> &'static str {
        Choice::ALL
            .iter()
            .find(|(c, _, _)| *c == self)
            .map_or("unrestricted", |(_, v, _)| v)
    }
}

/// A phase as the form holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct PhaseDraft {
    choice: Choice,
    /// One entry per line.
    names: String,
    ips: String,
}

impl PhaseDraft {
    pub(super) fn of(p: &HubPhase) -> Self {
        match p {
            HubPhase::Allow { names, ips } if names.is_empty() && ips.is_empty() => PhaseDraft {
                choice: Choice::None,
                ..PhaseDraft::default()
            },
            HubPhase::Allow { names, ips } => PhaseDraft {
                choice: Choice::Allow,
                names: names.join("\n"),
                ips: ips.join("\n"),
            },
            _ => PhaseDraft::default(),
        }
    }

    fn phase(&self) -> HubPhase {
        let lines = |s: &str| -> Vec<String> {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        };
        match self.choice {
            Choice::Unrestricted => HubPhase::Unrestricted,
            Choice::None => HubPhase::Allow {
                names: Vec::new(),
                ips: Vec::new(),
            },
            Choice::Allow => HubPhase::Allow {
                names: lines(&self.names),
                ips: lines(&self.ips),
            },
        }
    }
}

/// A rule as the form holds it: what was typed, shown again as typed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Draft {
    pub(super) name: String,
    /// A rule not stored yet.
    pub(super) new: bool,
    /// The GitLab instance; empty for any.
    pub(super) gitlab: String,
    /// `all`, `path` or `id`.
    pub(super) projects: String,
    pub(super) project_path: String,
    pub(super) project_id: String,
    /// Empty for any, `protected` or `unprotected`.
    pub(super) protection: String,
    pub(super) git_ref: String,
    pub(super) run: PhaseDraft,
    pub(super) build: PhaseDraft,
    pub(super) mode: RuleMode,
    /// The Blocked row a proposal was made for, and its phase: what a save from it saves an
    /// allow for, checked again then. Empty for none.
    pub(super) from_row: String,
    pub(super) from_phase: String,
}

impl Draft {
    fn is_fallback(&self) -> bool {
        self.name == DEFAULT_RULE
    }

    /// A rule to add: the Fallback when `fallback`, enforced; a project rule in dry-run.
    fn blank(fallback: bool) -> Self {
        Draft {
            name: if fallback {
                DEFAULT_RULE.to_string()
            } else {
                String::new()
            },
            new: true,
            projects: "path".to_string(),
            mode: if fallback {
                RuleMode::Enforce
            } else {
                RuleMode::DryRun
            },
            ..Draft::default()
        }
    }

    pub(super) fn of_rule(r: &EgressRuleRow) -> Self {
        let mut d = Draft {
            name: r.name.clone(),
            projects: "all".to_string(),
            run: PhaseDraft::of(&r.run),
            build: PhaseDraft::of(&r.build),
            mode: r.mode,
            ..Draft::default()
        };
        if let Some(s) = &r.subject {
            d.gitlab = s.gitlab.clone().unwrap_or_default();
            match &s.projects {
                crate::subject::Projects::Path(p) => {
                    d.projects = "path".into();
                    d.project_path = p.clone();
                }
                crate::subject::Projects::Id(id) => {
                    d.projects = "id".into();
                    d.project_id = id.to_string();
                }
                _ => {}
            }
            d.git_ref = s.git_ref.clone().unwrap_or_default();
            d.protection = match s.protected {
                Some(true) => "protected".into(),
                Some(false) => "unprotected".into(),
                None => String::new(),
            };
        }
        d
    }

    fn of_form(form: &[(String, String)]) -> Self {
        let get = |name: &str| field(form, name).unwrap_or("").trim().to_string();
        let phase = |prefix: &str| PhaseDraft {
            choice: Choice::ALL
                .iter()
                .find(|(_, v, _)| Some(*v) == field(form, prefix))
                .map_or(Choice::Unrestricted, |(c, _, _)| *c),
            names: field(form, &format!("{prefix}_names"))
                .unwrap_or("")
                .to_string(),
            ips: field(form, &format!("{prefix}_ips"))
                .unwrap_or("")
                .to_string(),
        };
        Draft {
            name: get("name"),
            new: field(form, "new") == Some("1"),
            gitlab: get("gitlab"),
            projects: get("projects"),
            project_path: get("project_path"),
            project_id: get("project_id"),
            protection: get("protection"),
            git_ref: get("git_ref"),
            run: phase("run"),
            build: phase("build"),
            mode: field(form, "mode")
                .and_then(RuleMode::parse)
                .unwrap_or(RuleMode::DryRun),
            from_row: field(form, "from_row")
                .filter(|id| vk_hub_proto::valid_id(id))
                .unwrap_or_default()
                .to_string(),
            from_phase: field(form, "from_phase")
                .filter(|p| matches!(*p, "run" | "build"))
                .unwrap_or_default()
                .to_string(),
        }
    }

    /// Its fields as the form posts them.
    fn fields(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![("name", self.name.clone())];
        if self.new {
            out.push(("new", "1".into()));
        }
        if !self.is_fallback() {
            out.extend([
                ("gitlab", self.gitlab.clone()),
                ("projects", self.projects.clone()),
                ("project_path", self.project_path.clone()),
                ("project_id", self.project_id.clone()),
                ("protection", self.protection.clone()),
                ("git_ref", self.git_ref.clone()),
            ]);
        }
        for (prefix, p) in [("run", &self.run), ("build", &self.build)] {
            let (choice, names, ips) = match prefix {
                "run" => ("run", "run_names", "run_ips"),
                _ => ("build", "build_names", "build_ips"),
            };
            out.push((choice, p.choice.value().to_string()));
            out.push((names, p.names.clone()));
            out.push((ips, p.ips.clone()));
        }
        out.push(("mode", self.mode.name().to_string()));
        if !self.from_row.is_empty() {
            out.push(("from_row", self.from_row.clone()));
            out.push(("from_phase", self.from_phase.clone()));
        }
        out
    }

    /// The subject it selects, or why it cannot be one, in plain words.
    fn subject(&self) -> Result<Option<Subject>, String> {
        if self.is_fallback() {
            return Ok(None);
        }
        let pattern = |s: &str, what: &str| {
            if s.contains(|c: char| c.is_whitespace() || c == ',') {
                Err(format!("{what} has no spaces or commas."))
            } else {
                Ok(())
            }
        };
        let mut terms = Vec::new();
        if !self.gitlab.is_empty() {
            terms.push(format!("gitlab {}", self.gitlab));
        }
        match self.projects.as_str() {
            "path" => {
                if self.project_path.is_empty() {
                    return Err("Give a project path pattern, such as wab/**.".into());
                }
                pattern(&self.project_path, "A project path pattern")?;
                terms.push(format!("projects {}", self.project_path));
            }
            "id" => {
                let Ok(id) = self.project_id.parse::<u64>() else {
                    return Err("A project ID is a number, as GitLab shows it.".into());
                };
                terms.push(format!("project-id {id}"));
            }
            _ => {}
        }
        if matches!(self.projects.as_str(), "path" | "id") && self.gitlab.is_empty() {
            return Err(
                "Choose the GitLab instance of a project path or ID: paths and IDs \
                        repeat across instances."
                    .into(),
            );
        }
        if !self.git_ref.is_empty() {
            if self.protection != "protected" {
                return Err(format!(
                    "A branch or tag pattern needs \u{201c}Protected only\u{201d}: anyone who \
                     can push can name a branch {}.",
                    self.git_ref
                ));
            }
            pattern(&self.git_ref, "A branch or tag pattern")?;
            terms.push(format!("ref {}", self.git_ref));
        }
        match self.protection.as_str() {
            "protected" => terms.push("protected".into()),
            "unprotected" => terms.push("unprotected".into()),
            _ => {}
        }
        if terms.is_empty() {
            terms.push("*".into());
        }
        Subject::parse(&terms.join(", "))
            .map(Some)
            .map_err(|e| capital(&e))
    }

    /// The change it asks of rule `old`, absent when it is new, and the rule as it would be
    /// stored; or why it may not be, in plain words.
    fn change(
        &self,
        old: Option<&EgressRuleRow>,
        generation: u64,
        actor: &str,
        now: u64,
    ) -> Result<(RuleChange, EgressRuleRow), String> {
        if !valid_rule_name(&self.name) {
            return Err("A rule's name is 1 to 64 letters, digits, '.', '_' and '-'.".into());
        }
        let change = RuleChange {
            name: self.name.clone(),
            subject: self.subject()?,
            run: Some(self.run.phase()),
            build: Some(self.build.phase()),
            mode: Some(self.mode),
        };
        let row = EgressRuleRow {
            name: change.name.clone(),
            subject: change.subject.clone(),
            run: self.run.phase(),
            build: self.build.phase(),
            mode: self.mode,
            version: old.map_or(1, |o| o.version.saturating_add(1)),
            generation: generation.saturating_add(1),
            created_at: old.map_or(now, |o| o.created_at),
            created_by: old.map_or_else(|| actor.to_string(), |o| o.created_by.clone()),
            updated_at: now,
            updated_by: actor.to_string(),
        };
        row.check().map_err(|e| format!("{}.", capital(&e)))?;
        Ok((change, row))
    }
}

/// `GET /egress?tab=rules&new=rule|fallback`: the form for a rule to add.
pub(super) fn new_page(rules: &Rules, fallback: bool, gitlabs: &[String], auth: &Auth) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, Tab::Rules, None);
    tab::state_callout(&mut h, rules);
    h.raw(if fallback {
        "<h2>Add the Fallback</h2>"
    } else {
        "<h2>Add a rule</h2>"
    });
    editor(&mut h, &Draft::blank(fallback), gitlabs, auth);
    h
}

/// The form for rule `r`, on its page.
pub(super) fn rule_forms(h: &mut Html, r: &EgressRuleRow, gitlabs: &[String], auth: &Auth) {
    h.raw("<section><h3>Change it</h3>");
    editor(h, &Draft::of_rule(r), gitlabs, auth);
    h.raw("<form method=\"post\" action=\"")
        .raw(ACTION_PATH)
        .raw("\">");
    pages::csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"preview\">")
        .raw("<input type=\"hidden\" name=\"remove\" value=\"1\">")
        .raw("<input type=\"hidden\" name=\"name\" value=\"")
        .text(&r.name)
        .raw("\"><button>Preview removing it</button></form></section>");
}

/// A hidden field.
fn hidden(h: &mut Html, name: &str, value: &str) {
    h.raw("<input type=\"hidden\" name=\"")
        .text(name)
        .raw("\" value=\"")
        .text(value)
        .raw("\">");
}

/// The form that previews `d`.
pub(super) fn editor(h: &mut Html, d: &Draft, gitlabs: &[String], auth: &Auth) {
    h.raw("<form class=\"wide rule\" method=\"post\" action=\"")
        .raw(ACTION_PATH)
        .raw("\">");
    pages::csrf_field(h, auth);
    hidden(h, "op", "preview");
    if d.new {
        hidden(h, "new", "1");
    }
    if !d.from_row.is_empty() {
        hidden(h, "from_row", &d.from_row);
        hidden(h, "from_phase", &d.from_phase);
    }
    if d.new && !d.is_fallback() {
        h.raw("<label>Name <input type=\"text\" name=\"name\" required maxlength=\"64\" ")
            .raw("pattern=\"[A-Za-z0-9._\\-]+\" autocomplete=\"off\" value=\"")
            .text(&d.name)
            .raw("\"></label>");
    } else {
        hidden(h, "name", &d.name);
    }
    if !d.is_fallback() {
        subject_fields(h, d, gitlabs);
    }
    for (prefix, label, p) in [
        ("run", "Run: job commands and services", &d.run),
        ("build", "Build: image build RUN steps", &d.build),
    ] {
        h.raw("<fieldset class=\"phase\"><legend>")
            .raw(label)
            .raw("</legend>");
        for (choice, value, text) in Choice::ALL {
            h.raw("<label><input type=\"radio\" name=\"")
                .raw(prefix)
                .raw("\" value=\"")
                .raw(value)
                .raw("\"");
            if p.choice == choice {
                h.raw(" checked");
            }
            h.raw("> ").raw(text).raw("</label>");
        }
        h.raw("<label>Domains, one per line <textarea name=\"")
            .raw(prefix)
            .raw("_names\" rows=\"3\" spellcheck=\"false\">")
            .text(&p.names)
            .raw("</textarea></label><label>IP ranges, one per line <textarea name=\"")
            .raw(prefix)
            .raw("_ips\" rows=\"3\" spellcheck=\"false\">")
            .text(&p.ips)
            .raw("</textarea></label><span class=\"sub\">With Allow listed destinations, ")
            .raw("an empty list allows none of its kind. A domain also allows every host under ")
            .raw(
                "it; an IP range is a CIDR, optionally with <code>:port</code>.</span></fieldset>",
            );
    }
    h.raw("<label>Mode <select name=\"mode\">");
    for (mode, label) in [
        (RuleMode::Enforce, "Enforce"),
        (RuleMode::DryRun, "Dry-run, report only"),
    ] {
        h.raw("<option value=\"").raw(mode.name()).raw("\"");
        if d.mode == mode {
            h.raw(" selected");
        }
        h.raw(">").raw(label).raw("</option>");
    }
    h.raw("</select></label> <button>Preview changes</button></form>");
}

/// The jobs a rule selects, as the namespaces page words them.
fn subject_fields(h: &mut Html, d: &Draft, gitlabs: &[String]) {
    h.raw("<fieldset><legend>Applies to</legend><label>GitLab <select name=\"gitlab\">")
        .raw("<option value=\"\">Any instance</option>");
    let mut names: BTreeSet<&str> = gitlabs.iter().map(String::as_str).collect();
    if !d.gitlab.is_empty() {
        names.insert(&d.gitlab);
    }
    for g in names {
        h.raw("<option value=\"").text(g).raw("\"");
        if g == d.gitlab {
            h.raw(" selected");
        }
        h.raw(">").text(g).raw("</option>");
    }
    h.raw("</select></label><label>Projects <select name=\"projects\">");
    for (value, label) in [
        ("all", "All projects"),
        ("path", "Path pattern"),
        ("id", "Project ID"),
    ] {
        h.raw("<option value=\"").raw(value).raw("\"");
        if d.projects == value {
            h.raw(" selected");
        }
        h.raw(">").raw(label).raw("</option>");
    }
    h.raw("</select></label><label>Path pattern <input type=\"text\" name=\"project_path\" ")
        .raw("placeholder=\"wab/**\" autocomplete=\"off\" value=\"")
        .text(&d.project_path)
        .raw("\"></label><label>Project ID <input type=\"number\" name=\"project_id\" min=\"1\" ")
        .raw("value=\"")
        .text(&d.project_id)
        .raw("\"></label><label>Protection <select name=\"protection\">");
    for (value, label) in [
        ("", "Protected and unprotected"),
        ("protected", "Protected only"),
        ("unprotected", "Unprotected only"),
    ] {
        h.raw("<option value=\"").raw(value).raw("\"");
        if d.protection == value {
            h.raw(" selected");
        }
        h.raw(">").raw(label).raw("</option>");
    }
    h.raw("</select></label><label>Branch or tag pattern <input type=\"text\" name=\"git_ref\" ")
        .raw("placeholder=\"release/*\" autocomplete=\"off\" value=\"")
        .text(&d.git_ref)
        .raw("\"></label><span class=\"sub\"><code>*</code> stays within a path component, ")
        .raw("<code>**</code> crosses them. A branch or tag pattern needs Protected only.")
        .raw("</span></fieldset>");
}

/// What a post asks.
enum Asked {
    Put(Box<Draft>),
    Remove(String),
}

/// `POST /egress/rules`: an operator's preview of a change to the rules, or its save.
pub(in crate::ui) async fn action(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let (auth, form) =
        match super::super::check_post_sized(req, ui, Role::Operator, MAX_RULE_FORM).await? {
            Ok(checked) => checked,
            Err((status, text)) => return Ok(message(status, text)),
        };
    let save = match field(&form, "op") {
        Some("preview") => false,
        Some("save") => true,
        _ => return Ok(message(StatusCode::BAD_REQUEST, "No such action.")),
    };
    let asked = if field(&form, "remove") == Some("1") {
        let Some(name) = field(&form, "name").filter(|n| valid_rule_name(n)) else {
            return Ok(message(StatusCode::BAD_REQUEST, "No such rule."));
        };
        Asked::Remove(name.to_string())
    } else {
        Asked::Put(Box::new(Draft::of_form(&form)))
    };
    let generation = field(&form, "generation").and_then(|g| g.parse::<u64>().ok());
    if save && generation.is_none() {
        return Ok(message(
            StatusCode::BAD_REQUEST,
            "A change is saved from its preview.",
        ));
    }
    let hub = ui.hub.clone();
    let actor = auth.session.principal();
    let (rules, gitlabs) = {
        let hub = hub.clone();
        blocking(move || {
            let gitlabs: Vec<String> = hub.db.gitlabs()?.into_iter().map(|(n, _)| n).collect();
            Ok((ops::list(&hub)?, gitlabs))
        })
        .await?
    };
    let now = crate::now_secs();
    let old = |name: &str| rules.rules.iter().find(|r| r.name == name);
    let (edit, change) = match &asked {
        Asked::Remove(name) => {
            if old(name).is_none() {
                return Ok(message(
                    StatusCode::NOT_FOUND,
                    "There is no such rule: it may have been removed.",
                ));
            }
            (Edit::Remove(name.clone()), None)
        }
        Asked::Put(d) => {
            let refused = match (d.new, old(&d.name)) {
                (true, Some(_)) => Some(format!(
                    "There is a rule named {} already: change it on its page.",
                    d.name
                )),
                (false, None) => Some("There is no such rule: it may have been removed.".into()),
                _ => None,
            };
            let made = match refused {
                Some(why) => Err(why),
                None => d.change(old(&d.name), rules.generation, &actor, now),
            };
            match made {
                Ok((change, row)) => (Edit::Put(Box::new(row)), Some(change)),
                Err(why) => {
                    return Ok(refused_page(
                        &rules,
                        d,
                        &why,
                        StatusCode::BAD_REQUEST,
                        &gitlabs,
                        &auth,
                    ));
                }
            }
        }
    };
    if !save {
        let (hub, wanted, generation, all) = (
            hub.clone(),
            edit.clone(),
            rules.generation,
            rules.rules.clone(),
        );
        let p = blocking(move || preview::preview(&hub, generation, &all, &wanted)).await?;
        let main = preview_page(&rules, &asked, &edit, &p, &gitlabs, &auth);
        return Ok(super::super::page(fleet::layout(
            "Egress", EGRESS, &auth, &main,
        )));
    }
    let generation = generation.unwrap_or_default();
    let (stored, name) = (hub.clone(), edit.name().to_string());
    let saved = blocking(move || match change {
        Some(c) => {
            let exists = !matches!(&asked, Asked::Put(d) if d.new);
            let allow = match &asked {
                Asked::Put(d) => allow_request(&stored, d)?,
                Asked::Remove(_) => None,
            };
            match allow {
                Some(req) => ops::save_allowing(&stored, &actor, &c, exists, generation, &req)
                    .map(|_| (Some(req.row), asked)),
                None => ops::save(&stored, &actor, &c, exists, generation).map(|_| (None, asked)),
            }
        }
        None => ops::remove_at(&stored, &actor, &name, generation).map(|_| (None, asked)),
    })
    .await;
    match saved {
        Ok((_, Asked::Remove(_))) => {
            ui.hub.egress_changed();
            Ok(see_other(tab::PATH))
        }
        // Back to the row it was proposed for, which says how its triage stands.
        Ok((Some(row), Asked::Put(d))) => {
            ui.hub.egress_changed();
            let phase = &d.from_phase;
            Ok(see_other(&format!(
                "{}{row}?saved={phase}",
                super::ROW_PREFIX
            )))
        }
        Ok((None, Asked::Put(d))) => {
            ui.hub.egress_changed();
            Ok(see_other(&rule_href(&d.name)))
        }
        Err(e) if e.downcast_ref::<RulesChanged>().is_some() => {
            let why = "The rules changed since your preview: preview the change again.";
            let d = match edit {
                Edit::Put(r) => Draft {
                    new: rules.rules.iter().all(|o| o.name != r.name),
                    ..Draft::of_rule(&r)
                },
                Edit::Remove(name) => {
                    return Ok(message(StatusCode::CONFLICT, &format!("{why} ({name})")));
                }
            };
            Ok(refused_page(
                &rules,
                &d,
                why,
                StatusCode::CONFLICT,
                &gitlabs,
                &auth,
            ))
        }
        Err(e) => Err(e),
    }
}

/// The allow a save of `d` saves for the row it was proposed for, checked again: the row is
/// still there, a hub rule still refused its destination to its latest jobs kept, in the phase
/// `d` names. `None` for a draft no proposal made, or one that no longer holds.
fn allow_request(hub: &crate::server::Hub, d: &Draft) -> Result<Option<AllowRequest>> {
    if d.from_row.is_empty() {
        return Ok(None);
    }
    let Some((row, jobs)) = super::kept(hub, &d.from_row)? else {
        return Ok(None);
    };
    let jobs: Vec<&crate::store::JobRow> = jobs.iter().collect();
    let Ok(seed) = proposal::of_row(&row, &jobs) else {
        return Ok(None);
    };
    let Some(phase) = proposal::phase_of_key(&d.from_phase).filter(|p| seed.phases.contains(p))
    else {
        return Ok(None);
    };
    Ok(Some(AllowRequest {
        row: d.from_row.clone(),
        phase,
        rule: d.name.clone(),
        claims: seed.latest().cloned(),
    }))
}

/// The form again, with why it was refused.
fn refused_page(
    rules: &Rules,
    d: &Draft,
    why: &str,
    status: StatusCode,
    gitlabs: &[String],
    auth: &Auth,
) -> Response<Body> {
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, Tab::Rules, None);
    tab::state_callout(&mut h, rules);
    h.raw("<p class=\"callout warn\" role=\"alert\">")
        .text(why)
        .raw("</p>");
    editor(&mut h, d, gitlabs, auth);
    html_response(status, fleet::layout("Egress", EGRESS, auth, &h))
}

/// The enforced rules a layer names, and its dry-run ones: `wab, wab-branches; dry-run
/// wab-release`, the Fallback as such.
fn layer_rules(l: &HubEgress) -> String {
    let named = |r: &str| match r {
        DEFAULT_RULE => "Fallback".to_string(),
        r => r.to_string(),
    };
    let mut out = match l.rules.as_slice() {
        [] => "none: may reach nothing".to_string(),
        rules => rules
            .iter()
            .map(|r| named(r))
            .collect::<Vec<_>>()
            .join(", "),
    };
    if !l.dry_run.is_empty() {
        let dry: Vec<String> = l.dry_run.iter().map(|d| named(&d.rule)).collect();
        out.push_str(&format!("; dry-run {}", dry.join(", ")));
    }
    out
}

/// How a phase changes, entry by entry: `unchanged`, `now unrestricted by hub rules`, `adds
/// partner.example.net; removes pypi.org`, `loses all access`. An entry added may change
/// nothing another entry already allowed.
fn change_text(before: &HubPhase, after: &HubPhase) -> String {
    if before == after {
        return "unchanged".to_string();
    }
    let entries = |p: &HubPhase| -> Option<Vec<String>> {
        match p {
            HubPhase::Allow { names, ips } => Some(names.iter().chain(ips).cloned().collect()),
            _ => None,
        }
    };
    let listed = |v: &[String]| match v {
        [] => String::new(),
        [a] => a.clone(),
        [a, b] => format!("{a}, {b}"),
        [a, b, rest @ ..] => format!("{a}, {b} and {} more", rest.len()),
    };
    match (entries(before), entries(after)) {
        (_, None) => "now unrestricted by hub rules".to_string(),
        (_, Some(a)) if a.is_empty() => "loses all access".to_string(),
        (None, Some(_)) => format!("now limited to {}", phase_summary(after)),
        (Some(b), Some(a)) => {
            let added: Vec<String> = a.iter().filter(|e| !b.contains(e)).cloned().collect();
            let removed: Vec<String> = b.iter().filter(|e| !a.contains(e)).cloned().collect();
            let mut parts = Vec::new();
            if !added.is_empty() {
                parts.push(format!("adds {}", listed(&added)));
            }
            if !removed.is_empty() {
                parts.push(format!("removes {}", listed(&removed)));
            }
            parts.join("; ")
        }
    }
}

/// The preview of `edit`, then the Save form carrying it unchanged and, for a rule, the form to
/// change it again.
fn preview_page(
    rules: &Rules,
    asked: &Asked,
    edit: &Edit,
    p: &Preview,
    gitlabs: &[String],
    auth: &Auth,
) -> Html {
    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, Tab::Rules, None);
    let exists = rules.rules.iter().any(|r| r.name == edit.name());
    h.raw("<h2>Preview: ");
    match edit {
        Edit::Remove(_) => h.raw("remove "),
        Edit::Put(_) if exists => h.raw("change "),
        Edit::Put(_) => h.raw("add "),
    };
    match edit.name() {
        DEFAULT_RULE => h.raw("the Fallback"),
        name => h.raw("rule ").text(name),
    };
    h.raw("</h2>");
    if let Asked::Put(d) = asked
        && !d.from_row.is_empty()
    {
        h.raw("<p class=\"sub\">Proposed for <a href=\"")
            .raw(super::ROW_PREFIX)
            .text(&d.from_row)
            .raw("\">a Blocked row</a>: saved, its triage moves to Allow saved, awaiting ")
            .raw("confirmation, if the rules as saved allow its destination to its project's ")
            .raw("latest job.</p>");
    }
    if !rules.enabled {
        h.raw("<p class=\"callout\">Hub rules are off: saved, this change restricts nothing ")
            .raw("until <code>[jobs] egress_rules = true</code>. Below is what it would do with ")
            .raw("them on.</p>");
    }
    if p.as_enforced {
        h.raw("<p class=\"callout\">In dry-run this rule blocks nothing. Below is what it would ")
            .raw("change once enforced; while hub rules are on, what jobs reach that it would ")
            .raw("refuse is reported as Would block.</p>");
    }
    if let Edit::Put(r) = edit {
        h.raw("<table class=\"kv\"><tbody>");
        pages::kv(&mut h, "Applies to", &applies_to(r, instances(gitlabs)));
        pages::kv(&mut h, "Run", &phase_summary(&r.run));
        pages::kv(&mut h, "Build", &phase_summary(&r.build));
        pages::kv_html(&mut h, "Mode", &{
            let mut b = Html::new();
            mode_badge(&mut b, r.mode);
            b
        });
        h.raw("</tbody></table>");
    }
    jobs_section(&mut h, p, instances(gitlabs));
    lost_section(&mut h, p, instances(gitlabs));

    // Save: the change previewed, unchanged, with the generation it was made against.
    h.raw("<form class=\"wide\" method=\"post\" action=\"")
        .raw(ACTION_PATH)
        .raw("\">");
    pages::csrf_field(&mut h, auth);
    hidden(&mut h, "op", "save");
    hidden(&mut h, "generation", &p.generation.to_string());
    match asked {
        Asked::Remove(name) => {
            hidden(&mut h, "remove", "1");
            hidden(&mut h, "name", name);
        }
        Asked::Put(d) => {
            for (name, value) in d.fields() {
                hidden(&mut h, name, &value);
            }
        }
    }
    h.raw("<button class=\"primary\">")
        .raw(match edit {
            Edit::Remove(_) => "Remove",
            Edit::Put(_) => "Save",
        })
        .raw("</button> <span class=\"sub\">Saved only if the rules are as previewed.</span>")
        .raw("</form>");
    match asked {
        Asked::Put(d) => {
            h.raw("<section><h3>Change it</h3>");
            editor(&mut h, d, gitlabs, auth);
            h.raw("</section>");
        }
        Asked::Remove(name) => {
            h.raw("<p><a href=\"")
                .text(rule_href(name))
                .raw("\">Keep it</a></p>");
        }
    }
    h
}

/// The groups of recent jobs the change affects or the rule selects, with their layer before
/// and after, their projects named by the hub's `instances`.
fn jobs_section(h: &mut Html, p: &Preview, instances: Instances<&str>) {
    h.raw("<section><h3>Recent jobs</h3>");
    if p.groups.is_empty() {
        h.raw("<p class=\"empty\">no recent job is affected or selected</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>jobs</th><th>project</th><th>ref</th>")
            .raw("<th>rules before</th><th>rules after</th><th>run</th><th>build</th>")
            .raw("</tr></thead><tbody>");
        for g in &p.groups {
            group_row(h, g, instances);
        }
        h.raw("</tbody></table>");
    }
    h.raw("<p class=\"sub\">From the history's latest ")
        .text(jobs_text(p.jobs_read as u64));
    if p.jobs_capped {
        h.raw(", which holds more");
    }
    if p.more_groups > 0 {
        h.raw("; ")
            .text(p.more_groups)
            .raw(" more groups not listed");
    }
    h.raw(". Entries added may allow nothing new where another entry already did.</p></section>");
}

fn group_row(h: &mut Html, g: &Group, instances: Instances<&str>) {
    h.raw("<tr><td class=\"num\"><a href=\"")
        .raw(super::super::jobs::DETAIL_PREFIX)
        .text(&g.latest)
        .raw("\" title=\"Their latest job\">")
        .text(g.jobs)
        .raw("</a></td><td>");
    match &g.claims {
        Some(c) => {
            let project = g.project.as_deref().unwrap_or(&c.project_path);
            h.node(&project_label(project, &c.gitlab, instances))
                .raw(" <span class=\"sub\">(project ")
                .text(c.project_id)
                .raw(")</span>");
        }
        None => {
            h.raw("<span class=\"sub\">jobs of no GitLab instance: the Fallback only</span>");
        }
    }
    h.raw("</td><td>");
    if let Some(c) = &g.claims {
        h.node(&c.git_ref)
            .raw(match (c.protected, g.protection_known) {
                (true, _) => " (protected)",
                (false, true) => "",
                (false, false) => " (protection not reported: read as unprotected)",
            });
    }
    h.raw("</td><td>")
        .text(layer_rules(&g.before))
        .raw("</td><td>")
        .text(layer_rules(&g.after));
    let replaces = g.before.rules == [DEFAULT_RULE]
        && !g.after.rules.is_empty()
        && !g.after.rules.iter().any(|r| r == DEFAULT_RULE);
    if replaces {
        h.raw(" <span class=\"badge\">Replaces the Fallback</span>");
    }
    if let Some(why) = &g.unplaceable {
        h.raw(" <span class=\"badge bad\" title=\"")
            .text(why)
            .raw("\">Would fail to place</span>");
    }
    h.raw("</td><td>")
        .text(change_text(&g.before.run, &g.after.run))
        .raw("</td><td>")
        .text(change_text(&g.before.build, &g.after.build))
        .raw("</td></tr>");
}

/// The destinations of Observed traffic the change would block, and how much evidence there is,
/// their projects named by the hub's `instances`.
fn lost_section(h: &mut Html, p: &Preview, instances: Instances<&str>) {
    h.raw("<section><h3>Observed destinations it would block</h3>");
    if p.affected.is_empty() {
        h.raw("<p class=\"callout warn\">Insufficient evidence: no job whose access it changes ")
            .raw("reported, so what they would lose is unknown.</p>");
    }
    h.raw("<ul class=\"access\">");
    for (key, label) in [("run", "Run: "), ("build", "Build: ")] {
        let Some(e) = p.affected.get(key) else {
            continue;
        };
        h.raw("<li>").raw(label);
        if e.complete == 0 {
            h.raw("<span class=\"badge warn\">Insufficient evidence</span> no job whose access ")
                .raw("it changes reported this phase completely, so what they would lose is ")
                .raw("unknown");
        } else {
            h.text(e.complete)
                .raw(" of ")
                .text(jobs_text(e.ran))
                .raw(" whose access it changes reported this phase completely");
        }
        h.raw("</li>");
    }
    if p.affected_unreported > 0 {
        h.raw("<li>")
            .text(jobs_text(p.affected_unreported))
            .raw(" whose access it changes sent no report</li>");
    }
    h.raw("</ul>");
    if p.dropped > 0 {
        h.raw("<p class=\"callout warn\">Incomplete: ")
            .text(p.dropped)
            .raw(" destinations used by the projects whose access it changes were not kept, ")
            .raw("past each project's bound, so they are not listed here.</p>");
    }
    if p.lost.is_empty() && p.maybe_lost.is_empty() {
        h.raw("<p class=\"empty\">none of the destinations reported</p>");
    }
    let more = |h: &mut Html, n: usize| {
        if n > 0 {
            h.raw("<p class=\"sub\">")
                .text(n)
                .raw(" more not listed.</p>");
        }
    };
    lost_table(h, &p.lost, instances);
    more(h, p.more_lost);
    if !p.maybe_lost.is_empty() {
        h.raw("<p>Blocked unless a lookup of a listed name resolved to them:</p>");
        lost_table(h, &p.maybe_lost, instances);
        more(h, p.more_maybe_lost);
    }
    if p.observed_capped {
        h.raw("<p class=\"sub\">Observed traffic was read only in part: there is more than a ")
            .raw("preview reads.</p>");
    }
    h.raw("<p class=\"sub\">From Observed traffic, as long as the job history keeps it.</p>")
        .raw("</section>");
}

fn lost_table(h: &mut Html, lost: &[Lost], instances: Instances<&str>) {
    if lost.is_empty() {
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>destination</th><th>phase</th>")
        .raw("<th>project</th><th class=\"num\">jobs</th><th>last used</th></tr></thead><tbody>");
    for l in lost {
        h.raw("<tr><td><code>")
            .node(&l.contact.text())
            .raw("</code></td><td>")
            .raw(match l.phase.as_str() {
                "run" => "Run",
                "build" => "Build",
                _ => "Other",
            })
            .raw("</td><td><a href=\"")
            .text(super::observed::subject_href(&l.subject))
            .raw("\">")
            .node(&l.subject.relabel(&l.who, instances))
            .raw("</a></td><td class=\"num\">")
            .text(l.jobs)
            .raw("</td><td>")
            .text(super::observed::date(l.last_day))
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

/// `1 job`, `2 jobs`.
fn jobs_text(n: u64) -> String {
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} job{plural}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::blocked::Subject as RowSubject;
    use crate::egress::observed::Contact;
    use vk_hub_proto::egress::{EgressDestination, EgressOutcome, EgressProtocol};

    fn lost(name: &str, uncertain: bool) -> Lost {
        Lost {
            subject: RowSubject::Key { key: "k".into() },
            who: "k".into(),
            phase: "run".into(),
            contact: Contact {
                outcome: EgressOutcome::Observed,
                protocol: EgressProtocol::Dns,
                destination: EgressDestination::domain(name),
            },
            jobs: 1,
            last_day: 0,
            uncertain,
        }
    }

    #[test]
    fn each_list_of_lost_destinations_says_how_many_it_leaves_out() {
        let p = Preview {
            generation: 0,
            as_enforced: false,
            groups: Vec::new(),
            more_groups: 0,
            jobs_read: 0,
            jobs_capped: false,
            lost: vec![lost("a.example", false)],
            maybe_lost: vec![lost("b.example", true)],
            more_lost: 2,
            more_maybe_lost: 3,
            affected: Default::default(),
            affected_unreported: 0,
            observed_capped: false,
            dropped: 0,
        };
        let mut h = Html::new();
        lost_section(&mut h, &p, Instances::None);
        let out = h.into_string();
        let (sure, maybe) = out.split_once("Blocked unless a lookup").unwrap();
        assert!(sure.contains("2 more not listed."), "{out}");
        assert!(maybe.contains("3 more not listed."), "{out}");
        assert!(!out.contains("Incomplete"), "{out}");
        let mut h = Html::new();
        lost_section(&mut h, &Preview { dropped: 4, ..p }, Instances::None);
        let out = h.into_string();
        assert!(
            out.contains("Incomplete: 4 destinations used by the projects whose access"),
            "{out}"
        );
    }
}
