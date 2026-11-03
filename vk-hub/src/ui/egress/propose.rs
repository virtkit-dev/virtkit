//! `/egress?tab=rules&propose=…`: an operator's proposal of a hub rule allowing a destination a
//! hub rule refused ([`crate::egress::proposal`]): from a Blocked row, `propose=<row ID>`, or
//! from a contact of Observed traffic the rules saved now leave outside,
//! `propose=observed&project=<subject>&contact=<contact>`, in one `phase`. The page chooses the
//! rule to change — one that applies to the project's jobs now, or a new rule for exactly that
//! project — and prefills the editor with the change ([`super::editor`]): nothing is saved but
//! through its Preview → Save, and a save from a row's proposal checks the row again. Its
//! choices are a plain GET form, so the page reads the same however it is reached.
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
use crate::egress::blocked::{Subject, instances};
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
                    "There is no such row. No job in the history shares it.".into(),
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
                    "A proposal from Observed traffic must name its phase.".into()
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
                    "The project's jobs in the history no longer show that destination in \
                     that phase."
                        .into(),
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
            "Only an operator can propose an egress rule.",
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
    let instances = instances(&p.gitlabs);
    let who = seed.subject.label(seed.project.as_deref(), "", instances);
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
    h.raw("in the ").text(phases.join(" and ")).raw(" phase.");
    match &p.row {
        Some(id) => {
            h.raw(" See <a href=\"")
                .raw(ROW_PREFIX)
                .text(id)
                .raw("\">its Blocked row</a>.");
        }
        None => {
            h.raw(" The rules saved now leave it outside for some of these jobs. See ")
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
                .raw(" and its subdomains. Nothing broader is proposed. You can type a broader ")
                .raw("entry yourself, but it also allows destinations that these reports do not ")
                .raw("show.");
        }
    }
    h.raw(" Another layer, such as a node's cap or the job's own narrowing, may still refuse ")
        .raw("it.</p>");

    let Some(chosen) = chosen else {
        h.raw("<p class=\"empty\">No rule can take this entry. Every rule that applies to these ")
            .raw("jobs already allows it in this phase, and a new rule can select only a GitLab ")
            .raw("project.</p>");
        return h;
    };
    let mut draft = match &chosen {
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
                    .text(super::lower(&applies_to(r, instances)))
                    .raw(". The entry would be allowed to every job that this rule selects, not ")
                    .raw("only these jobs.</p>");
            }
            if r.mode == RuleMode::DryRun {
                h.raw("<p class=\"callout\">")
                    .text(rule_name(r))
                    .raw(" is in dry-run. Once you save, it no longer reports this destination ")
                    .raw("as Would block, and it still blocks nothing until enforced. To enforce ")
                    .raw("it, set the editor's Mode and preview that like any change.</p>");
            }
            d
        }
        Chosen::New(subject) => {
            let base = match (ask.base, proposal::enforced_fallback(rules)) {
                (Some(b), Some(_)) => b,
                _ => Base::Entry,
            };
            if base == Base::Fallback {
                h.raw("<p class=\"callout warn\">Starting from the Fallback copies the ")
                    .raw("Fallback's lists to every job of this project that the rule selects, ")
                    .raw("protected refs included. Those jobs keep what any other enforced rule ")
                    .raw("allows them as well.</p>");
            }
            if proposal::mixed(seed, rules) {
                h.raw("<p class=\"callout warn\">An enforced rule selects some of these jobs, ")
                    .raw("and only the Fallback applies to the others. Rules add up. If you start ")
                    .raw("from the Fallback, the jobs that an enforced rule selects also get the ")
                    .raw("Fallback's lists. If you start from the entry alone, the jobs that only ")
                    .raw("the Fallback applies to lose the Fallback's lists once the new rule is ")
                    .raw("enforced. The preview shows both.</p>");
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
    if let Some(id) = &p.row {
        draft.from_row = id.clone();
        draft.from_phase = proposal::phase_key(phase).unwrap_or("run").to_string();
    }
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
    h.raw("</h3><p class=\"sub\">Prefilled. Review it, then choose Preview changes. The ")
        .raw("preview's Save is refused if the rules change in between.");
    if p.row.is_some() {
        h.raw(" If the saved rules allow the destination to the project's latest job, saving ")
            .raw("moves the row's triage to Allow saved, awaiting confirmation.");
    }
    h.raw("</p>");
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
            .text(applies_to(t.rule, instances(&p.gitlabs)))
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
