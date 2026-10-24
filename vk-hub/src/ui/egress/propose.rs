//! `/egress?tab=rules&propose=…`: an operator's proposal of a hub rule allowing a destination a
//! hub rule refused ([`crate::egress::proposal`]): from a Blocked row, `propose=<row ID>`, or
//! from a contact of Observed traffic the rules saved now leave outside,
//! `propose=observed&project=<subject>&contact=<contact>`, in one `phase`. The page chooses the
//! rule to change — one that applies to the project's jobs now, or a new rule for exactly that
//! project — and prefills the editor with the change ([`super::editor`]): nothing is saved but
//! through its Preview → Save. Its choices are a plain GET form, so the page reads the same
//! however it is reached.
//!
//! The destination is a guest's: it goes through [`Html::node`], and is never broadened.

use anyhow::Result;
use hyper::{Response, StatusCode};
use vk_hub_proto::egress::{EgressDimension, EgressPhase};

use super::super::html::Html;
use super::super::jobs::percent_encode;
use super::super::{Auth, Body, Ui, blocking, field, fleet, message, page};
use super::editor::{Draft, PhaseDraft, editor};
use super::rules::{self as tab, applies_to, rule_href, rule_name};
use super::{PATH as EGRESS, ROW_PREFIX, Tab};
use crate::egress::blocked::Subject;
use crate::egress::observed::Contact;
use crate::egress::proposal::{self, Base, By, NoProposal, Seed, Standing};
use crate::egress::rules::{self as ops, Rules, claims_for, claims_of};
use crate::server::Hub;
use crate::store::{ObservedFilter, Role, RuleMode};

/// The query's value of `propose` for a contact of Observed traffic.
const OBSERVED: &str = "observed";

/// The new rule, as the target's value.
const NEW: &str = "new";

/// What the proposal is made from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum From {
    Row(String),
    Contact { subject: Subject, contact: Contact },
}

/// What the page is asked: the evidence, the phase and the choices made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Ask {
    from: From,
    phase: Option<EgressPhase>,
    /// A rule's name, or [`NEW`].
    target: Option<String>,
    by: By,
    base: Option<Base>,
}

impl Ask {
    /// The proposal `query` asks for, if it asks for one.
    pub(super) fn of(query: &[(String, String)]) -> Option<Ask> {
        let from = match field(query, "propose")? {
            OBSERVED => From::Contact {
                subject: field(query, "project").and_then(Subject::parse)?,
                contact: field(query, "contact").and_then(Contact::parse)?,
            },
            id if vk_hub_proto::valid_id(id) => From::Row(id.to_string()),
            _ => return None,
        };
        Some(Ask {
            from,
            phase: field(query, "phase").and_then(proposal::phase_of_key),
            target: field(query, "target")
                .filter(|t| *t == NEW || vk_hub_proto::egress::valid_rule_name(t))
                .map(str::to_string),
            by: match field(query, "by") {
                Some("path") => By::Path,
                _ => By::Id,
            },
            base: match field(query, "base") {
                Some("fallback") => Some(Base::Fallback),
                Some("entry") => Some(Base::Entry),
                _ => None,
            },
        })
    }
}

/// The proposal for row `id` in `phase`, as an attribute's value.
pub(super) fn row_href(id: &str, phase: EgressPhase) -> String {
    format!(
        "{}&propose={id}&phase={}",
        tab::PATH,
        proposal::phase_key(phase).unwrap_or("run")
    )
}

/// The proposal for `subject`'s contact `contact` in phase `key`, as an attribute's value.
pub(super) fn contact_href(subject: &Subject, key: &str, contact: &Contact) -> String {
    format!(
        "{}&propose={OBSERVED}&project={}&phase={}&contact={}",
        tab::PATH,
        percent_encode(&subject.param()),
        percent_encode(key),
        percent_encode(&contact.key())
    )
}

/// What the page shows.
struct Proposing {
    seed: Seed,
    /// The row it is for, when it is one's.
    row: Option<String>,
    rules: Rules,
    gitlabs: Vec<String>,
}

/// The seed `ask` names, from the store; `Err` says why there is none.
fn load(hub: &Hub, ask: &Ask) -> Result<Result<Proposing, String>> {
    let (seed, row) = match &ask.from {
        From::Row(id) => {
            let Some((row, jobs)) = super::kept(hub, id)? else {
                return Ok(Err(
                    "There is no such row: no job of the history shares it.".into(),
                ));
            };
            let jobs: Vec<&crate::store::JobRow> = jobs.iter().collect();
            match proposal::of_row(&row, &jobs) {
                Ok(seed) => (seed, Some(id.clone())),
                Err(why) => return Ok(Err(refused(why))),
            }
        }
        From::Contact { subject, contact } => {
            let Some(phase) = ask.phase.and_then(proposal::phase_key) else {
                return Ok(Err(
                    "A proposal from Observed traffic names its phase.".into()
                ));
            };
            let filter = ObservedFilter {
                phase: Some(phase),
                protection: None,
            };
            let uses = hub.db.observed_uses(subject, filter)?;
            let Some(u) = uses
                .iter()
                .find(|u| u.contact == *contact && u.phase == phase)
            else {
                return Ok(Err(
                    "Its jobs no longer reached that destination in that phase.".into(),
                ));
            };
            let project = hub
                .db
                .observed_subjects()?
                .into_iter()
                .find(|(param, _)| *param == subject.param())
                .and_then(|(_, s)| s.project);
            // Its latest job's claims first, then each ref's.
            let mut claims = Vec::new();
            if let Some(j) = hub.db.job(&u.last_job)? {
                claims.push(claims_of(&j));
            }
            for (git_ref, protection) in u.refs.keys() {
                let c = claims_for(subject, project.as_deref(), protection, git_ref);
                if !claims.contains(&c) {
                    claims.push(c);
                }
            }
            let (_, rules) = hub.db.egress_rules()?;
            match proposal::of_contact(
                subject,
                project.as_deref(),
                contact.protocol,
                &contact.destination,
                proposal::phase_of_key(phase).unwrap_or(EgressPhase::Run),
                claims,
                &rules,
            ) {
                Ok(seed) => (seed, None),
                Err(why) => return Ok(Err(refused(why))),
            }
        }
    };
    Ok(Ok(Proposing {
        seed,
        row,
        rules: ops::list(hub)?,
        gitlabs: hub.db.gitlabs()?.into_iter().map(|(n, _)| n).collect(),
    }))
}

/// Why no rule is proposed, as the page says it.
fn refused(why: NoProposal) -> String {
    let mut text = super::capital(why.text());
    text.push('.');
    text
}

/// `GET /egress?tab=rules&propose=…` ([`Ask::of`]): operators only.
pub(super) async fn get(ask: Ask, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    if auth.session.role < Role::Operator {
        return Ok(message(
            StatusCode::FORBIDDEN,
            "Proposing an egress rule takes an operator.",
        ));
    }
    let (hub, wanted) = (ui.hub.clone(), ask.clone());
    let loaded = blocking(move || load(&hub, &wanted)).await?;
    let p = match loaded {
        Ok(p) => p,
        Err(why) => return Ok(message(StatusCode::NOT_FOUND, &why)),
    };
    let main = proposal_page(&ask, &p, auth);
    Ok(page(fleet::layout("Egress", EGRESS, auth, &main)))
}

/// The change chosen: a rule extended, or a new one.
enum Chosen<'a> {
    Rule(&'a crate::store::EgressRuleRow),
    New(crate::subject::Subject),
}

fn proposal_page(ask: &Ask, p: &Proposing, auth: &Auth) -> Html {
    let seed = &p.seed;
    let rules = &p.rules.rules;
    let phase = ask
        .phase
        .filter(|ph| seed.phases.contains(ph))
        .or(seed.phases.first().copied())
        .unwrap_or(EgressPhase::Run);
    let who = seed.subject.text(seed.project.as_deref(), "");
    let who = match &seed.subject {
        Subject::Gitlab { .. } => who,
        Subject::Key { .. } => "the jobs of this key".to_string(),
    };
    let targets = proposal::targets(seed, rules, phase);
    let new_subject = proposal::new_subject(seed, ask.by)
        .or_else(|| proposal::new_subject(seed, By::Id).filter(|_| ask.by == By::Path));
    let chosen = match ask.target.as_deref() {
        Some(NEW) => new_subject.clone().map(Chosen::New),
        Some(name) => targets
            .iter()
            .find(|t| t.rule.name == name && t.standing == Standing::Adds)
            .map(|t| Chosen::Rule(t.rule)),
        None => None,
    }
    .or_else(|| {
        targets
            .iter()
            .find(|t| t.standing == Standing::Adds)
            .map(|t| Chosen::Rule(t.rule))
    })
    .or_else(|| new_subject.clone().map(Chosen::New));

    let mut h = Html::new();
    h.raw("<h1>Egress</h1>");
    super::tabs(&mut h, Tab::Rules, None);
    tab::state_callout(&mut h, &p.rules);
    h.raw("<h2>Propose allowing <code>")
        .node(&seed.entry.text)
        .raw("</code> for ")
        .node(&who)
        .raw("</h2><p class=\"sub\">");
    let what = match seed.view {
        super::View::WouldBlock => "A dry-run hub rule would have refused ",
        _ => "A hub rule refused ",
    };
    h.raw(what)
        .text(crate::egress::protocol_text(seed.protocol))
        .raw(" <code>")
        .node(&crate::egress::destination_text(&seed.destination))
        .raw("</code> to its jobs, ");
    let phases: Vec<String> = seed
        .phases
        .iter()
        .map(|ph| crate::egress::phase_text(*ph).to_ascii_lowercase())
        .collect();
    h.raw("in the ").text(phases.join(" and ")).raw(" phase");
    match &p.row {
        Some(id) => {
            h.raw(": <a href=\"")
                .raw(ROW_PREFIX)
                .text(id)
                .raw("\">its Blocked row</a>.");
        }
        None => {
            h.raw("; the rules saved now leave it outside for some of them: ")
                .raw("<a href=\"")
                .text(super::observed::subject_href(&seed.subject))
                .raw("\">its Observed traffic</a>.");
        }
    }
    h.raw("</p>");

    choices(&mut h, ask, p, phase, &targets, new_subject.is_some());

    // What the entry allows, said plainly.
    h.raw("<p class=\"callout\">");
    match seed.entry.dimension {
        EgressDimension::Ip => {
            h.raw("The entry <code>")
                .node(&seed.entry.text)
                .raw("</code> allows that address alone, on that port, over TCP and UDP.");
        }
        _ => {
            h.raw("The entry <code>")
                .node(&seed.entry.text)
                .raw("</code> allows ")
                .node(&seed.entry.text)
                .raw(" and its subdomains. Nothing broader is proposed: a broader entry is ")
                .raw("yours to type, and allows destinations absent from these reports.");
        }
    }
    h.raw(" Another layer — a node's cap, the job's own narrowing — may still refuse it.</p>");

    let Some(chosen) = chosen else {
        h.raw("<p class=\"empty\">No rule can take it: none that applies to these jobs lacks ")
            .raw("it in this phase, and a new rule selects a GitLab project only.</p>");
        return h;
    };
    let draft = match &chosen {
        Chosen::Rule(r) => {
            let mut d = Draft::of_rule(r);
            let changed =
                proposal::rule_phase(r, phase).map(|ph| proposal::with_entry(ph, &seed.entry));
            match (phase, changed) {
                (EgressPhase::Build, Some(ph)) => d.build = PhaseDraft::of(&ph),
                (_, Some(ph)) => d.run = PhaseDraft::of(&ph),
                _ => {}
            }
            if r.subject.as_ref().is_none_or(|s| !selects_only(s, seed)) {
                h.raw("<p class=\"callout warn\">")
                    .text(rule_name(r))
                    .raw(" applies to ")
                    .text(applies_to(r).to_lowercase())
                    .raw(": the entry is allowed to every job it selects, not only these.</p>");
            }
            if r.mode == RuleMode::DryRun {
                h.raw("<p class=\"callout\">")
                    .text(rule_name(r))
                    .raw(" is in dry-run: saved, it no longer reports this destination as Would ")
                    .raw("block, and blocks nothing until enforced. Enforcing it is the editor's ")
                    .raw("Mode, previewed like any change.</p>");
            }
            d
        }
        Chosen::New(subject) => {
            let base = match (ask.base, proposal::enforced_fallback(rules)) {
                (Some(b), Some(_)) => b,
                _ => Base::Entry,
            };
            if base == Base::Fallback {
                h.raw("<p class=\"callout warn\">Starting from the Fallback copies its lists to ")
                    .raw("every job of this project the rule selects, protected refs included, ")
                    .raw("beside what any enforced rule allows them.</p>");
            }
            if proposal::mixed(seed, rules) {
                h.raw("<p class=\"callout warn\">An enforced rule selects some of these jobs and ")
                    .raw(
                        "the Fallback alone applies to others: rules add up, so starting from the ",
                    )
                    .raw(
                        "Fallback adds its lists to the former, and starting from the entry alone ",
                    )
                    .raw("takes the Fallback's from the latter once enforced. The preview shows ")
                    .raw("both.</p>");
            }
            let (run, build) = proposal::new_phases(seed, rules, phase, base);
            let (projects, project_path, project_id) = match &subject.projects {
                crate::subject::Projects::Path(path) => ("path", path.clone(), String::new()),
                crate::subject::Projects::Id(id) => ("id", String::new(), id.to_string()),
                _ => ("all", String::new(), String::new()),
            };
            Draft {
                name: proposal::new_name(seed, rules),
                new: true,
                gitlab: subject.gitlab.clone().unwrap_or_default(),
                projects: projects.to_string(),
                project_path,
                project_id,
                run: PhaseDraft::of(&run),
                build: PhaseDraft::of(&build),
                mode: RuleMode::DryRun,
                ..Draft::default()
            }
        }
    };
    h.raw("<section><h3>");
    match &chosen {
        Chosen::Rule(r) => {
            h.raw("Change <a href=\"")
                .text(rule_href(&r.name))
                .raw("\">")
                .text(rule_name(r))
                .raw("</a>");
        }
        Chosen::New(_) => {
            h.raw("A new rule, in dry-run");
        }
    }
    h.raw("</h3><p class=\"sub\">Prefilled: review it, then Preview changes. Save, from the ")
        .raw("preview, is refused if the rules change in between.</p>");
    editor(&mut h, &draft, &p.gitlabs, auth);
    h.raw("</section>");
    h
}

/// Whether subject `s` selects the seed's project alone.
fn selects_only(s: &crate::subject::Subject, seed: &Seed) -> bool {
    let Subject::Gitlab {
        instance,
        project_id,
    } = &seed.subject
    else {
        return false;
    };
    s.gitlab.as_deref() == Some(instance.as_str())
        && match &s.projects {
            crate::subject::Projects::Id(id) => id == project_id,
            crate::subject::Projects::Path(p) => {
                proposal::exact_path(p) && seed.project.as_deref() == Some(p.as_str())
            }
            _ => false,
        }
}

/// The form choosing the phase, the rule to change and, for a new rule, how it selects the
/// project and what it starts from.
fn choices(
    h: &mut Html,
    ask: &Ask,
    p: &Proposing,
    phase: EgressPhase,
    targets: &[proposal::Target],
    new: bool,
) {
    let seed = &p.seed;
    h.raw("<form class=\"wide\" method=\"get\" action=\"")
        .raw(EGRESS)
        .raw("\"><input type=\"hidden\" name=\"tab\" value=\"rules\">");
    let hidden = |h: &mut Html, name: &str, value: &str| {
        h.raw("<input type=\"hidden\" name=\"")
            .text(name)
            .raw("\" value=\"")
            .text(value)
            .raw("\">");
    };
    match &ask.from {
        From::Row(id) => hidden(h, "propose", id),
        From::Contact { subject, contact } => {
            hidden(h, "propose", OBSERVED);
            hidden(h, "project", &subject.param());
            hidden(h, "contact", &contact.key());
        }
    }
    if seed.phases.len() > 1 {
        h.raw("<fieldset><legend>Phase</legend>");
        for ph in &seed.phases {
            let key = proposal::phase_key(*ph).unwrap_or("run");
            h.raw("<label><input type=\"radio\" name=\"phase\" value=\"")
                .raw(key)
                .raw("\"");
            if *ph == phase {
                h.raw(" checked");
            }
            h.raw("> ")
                .text(crate::egress::phase_text(*ph))
                .raw("</label>");
        }
        h.raw("</fieldset>");
    } else {
        hidden(h, "phase", proposal::phase_key(phase).unwrap_or("run"));
    }
    h.raw("<fieldset><legend>Rule</legend>");
    let first_adds = targets.iter().find(|t| t.standing == Standing::Adds);
    let chosen = |name: &str| match ask.target.as_deref() {
        Some(t) => t == name,
        None => first_adds.map(|t| t.rule.name.as_str()) == Some(name),
    };
    for t in targets {
        h.raw("<label><input type=\"radio\" name=\"target\" value=\"")
            .text(&t.rule.name)
            .raw("\"");
        if t.standing != Standing::Adds {
            h.raw(" disabled");
        } else if chosen(&t.rule.name) {
            h.raw(" checked");
        }
        h.raw("> <strong>")
            .text(rule_name(t.rule))
            .raw("</strong> <span class=\"sub\">")
            .text(applies_to(t.rule))
            .raw("; applies to ")
            .text(t.applies)
            .raw(" of the ")
            .text(seed.claims.len())
            .raw(" jobs");
        match t.standing {
            Standing::Adds => {}
            Standing::AlreadyAllows => {
                h.raw("; already allows it in this phase, so another rule or layer refuses it");
            }
            Standing::Unrestricted => {
                h.raw("; unrestricted in this phase");
            }
        }
        h.raw("</span></label>");
    }
    if new {
        h.raw("<label><input type=\"radio\" name=\"target\" value=\"")
            .raw(NEW)
            .raw("\"");
        if ask.target.as_deref() == Some(NEW) || (ask.target.is_none() && first_adds.is_none()) {
            h.raw(" checked");
        }
        h.raw("> A new rule for exactly this project</label>");
        let path = proposal::new_subject(seed, By::Path).is_some();
        h.raw("<label>Selected by <select name=\"by\"><option value=\"id\">its project ID")
            .raw("</option>");
        if path {
            h.raw("<option value=\"path\"");
            if ask.by == By::Path {
                h.raw(" selected");
            }
            h.raw(">its path, exactly</option>");
        }
        h.raw("</select></label>");
        if proposal::enforced_fallback(&p.rules.rules).is_some() {
            let base = ask.base.unwrap_or(Base::Entry);
            h.raw("<label>Starting from <select name=\"base\">");
            for (value, b, label) in [
                (
                    "entry",
                    Base::Entry,
                    "the entry alone, the other phase allowing none",
                ),
                (
                    "fallback",
                    Base::Fallback,
                    "the Fallback's lists, the entry added",
                ),
            ] {
                h.raw("<option value=\"").raw(value).raw("\"");
                if base == b {
                    h.raw(" selected");
                }
                h.raw(">").raw(label).raw("</option>");
            }
            h.raw("</select></label>");
        }
    }
    h.raw("</fieldset><button>Prefill the editor</button></form>");
}
