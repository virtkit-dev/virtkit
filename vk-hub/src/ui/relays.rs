//! GitLab relay updates: the `/updates` section ([`updates`]) and `/relay/<id>/action`
//! handler, using the same operation as `vk-hub relays update`. The relay list is on `/gitlab`
//! ([`super::clients`]).
//!
//! Runners added on the hub, as `vk-hub relays runners add|remove` adds and removes them:
//! `/relay/<id>/add-runner` is an operator's form, a plain POST to the relay's action whose
//! refusal shows the form again with what was filled in but the token, which is never sent
//! back. *Remove*, on a runner's row, asks first.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::Outcome;
use vk_hub_proto::client::Placement;
use vk_hub_proto::gitlab::{Operation, RunnerFailure, RunnerToken};

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::csrf_field;
use super::{Auth, Body, Ui, actions, blocking, field, page, updates};
use crate::relays::{self as ops, RelayView, RunnerOrigin, RunnerSettings};
use crate::server::Hub;
use crate::store::{NotEnrolled, Program, RelayCommandRow, Role};

/// Where a relay's update is posted: this, its ID, then `/action`.
const PREFIX: &str = "/relay/";

/// The relay `/relay/<id>/action` is for, if `path` is that for a well-formed ID.
pub(super) fn action_target(path: &str) -> Option<&str> {
    path.strip_prefix(PREFIX)?
        .strip_suffix("/action")
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// The page adding a runner to relay `id`.
pub(super) fn add_runner_href(id: &str) -> String {
    format!("{PREFIX}{id}{ADD_RUNNER_SUFFIX}")
}

const ADD_RUNNER_SUFFIX: &str = "/add-runner";

/// The relay `/relay/<id>/add-runner` is for, if `path` is that for a well-formed ID.
pub(super) fn add_runner_target(path: &str) -> Option<&str> {
    path.strip_prefix(PREFIX)?
        .strip_suffix(ADD_RUNNER_SUFFIX)
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// The ops posted to `/relay/<id>/action` for runners.
const ADD_RUNNER: &str = "add-runner";
const REMOVE_RUNNER: &str = "remove-runner";

/// Relays, as their updates show them, looked up, checked and issued as `vk-hub relays update`
/// issues them.
pub(super) static KIND: updates::Kind = updates::Kind {
    noun: "relay",
    heading: "GitLab adapters",
    column: "ADAPTER",
    program: Program::Gitlab,
    note: "A relay downloads the release and stops asking GitLab for jobs. Once its requests \
           out to GitLab have ended, the relay restarts on the release. Its running jobs go on, \
           and their logs resume where GitLab has them. If the release does not come up, the \
           relay rolls back to the binary it ran before, once the relay's supervisor restarts \
           it.",
    question: "Update this relay? The relay stops asking GitLab for jobs and restarts on the \
               release. Its running jobs go on. If the release does not come up, the relay goes \
               back to the binary it ran before, once its supervisor restarts it.",
    command_ttl: ops::COMMAND_TTL,
    allow: "<code>[hub] allow</code>, which lacks <code>update</code>",
    allow_downgrade: "<code>[hub] allow_downgrade</code>",
    started: updates::sent,
    ops: updates::Ops {
        find: |hub, id| {
            let Some(view) = ops::detail(hub, id)? else {
                return Ok(None);
            };
            let last = last_update(hub, id)?;
            Ok(Some(peer(view, last)))
        },
        check: |hub, id, release| {
            let row = hub
                .db
                .relay(id)?
                .ok_or_else(|| NotEnrolled(id.to_string()))?;
            ops::check_update(&row, release)
        },
        issue: |hub, actor, id, release, running| {
            ops::update_as_shown(hub, actor, id, release, running).map(|c| c.id)
        },
    },
};

/// The last update the hub issued relay `id`.
fn last_update(hub: &Hub, id: &str) -> Result<Option<RelayCommandRow>> {
    Ok(hub
        .db
        .relay_commands(id)?
        .into_iter()
        .filter(|c| matches!(c.command.op, Operation::Update { .. }))
        .max_by_key(|c| c.seq))
}

/// Relay `v` as its update shows it, `last` the last update the hub issued it.
fn peer(v: RelayView, last: Option<RelayCommandRow>) -> updates::Peer {
    let inventory = v.row.inventory.as_ref();
    updates::Peer {
        page: None,
        action: format!("{PREFIX}{}/action", v.id),
        hostname: v.row.hostname.clone(),
        version: inventory.map(|i| i.version.clone()),
        connected: v.connected,
        takes_updates: ops::takes_updates(&v.row),
        allows_downgrade: None,
        requires_signed: inventory.is_some_and(|i| i.requires_signed),
        reported: v.row.report.as_ref().and_then(|r| r.update.clone()),
        last: last.and_then(|c| {
            let Operation::Update { version, .. } = c.command.op else {
                return None;
            };
            Some(updates::Issued {
                id: c.command.id,
                version,
                issued_at: c.issued_at,
                expires_at: c.command.expires_at,
                outcome: c.outcome,
            })
        }),
        id: v.id,
    }
}

/// Every relay as `/updates` shows its update, with the last one the hub issued it.
pub(super) fn updatables(hub: &Hub) -> Result<Vec<updates::Peer>> {
    ops::views(hub)?
        .into_iter()
        .map(|view| {
            let last = last_update(hub, &view.id)?;
            Ok(peer(view, last))
        })
        .collect()
}

/// `POST /relay/<id>/action`: `op=update`, an operator's update of the relay, asked again first;
/// `op=add-runner`, a runner added from [`add_runner_page`]'s form; `op=remove-runner`, a
/// runner added on the hub removed, asked first.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
    id: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    match field(&form, "op") {
        Some("update") => updates::update(ui, site, htmx, &auth, &form, &KIND, id).await,
        Some(ADD_RUNNER) => add_runner(ui, &auth, &form, id).await,
        Some(REMOVE_RUNNER) => remove_runner(ui, site, htmx, &auth, &form, id).await,
        _ => Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "No such action.",
        )),
    }
}

/// What the add-runner form was filled in with, but the token.
struct RunnerFields {
    name: String,
    pool: String,
    labels: String,
    envelope: String,
    limit: String,
    request_concurrency: String,
}

impl Default for RunnerFields {
    /// What `vk-hub relays runners add` defaults to.
    fn default() -> Self {
        RunnerFields {
            name: String::new(),
            pool: "default".into(),
            labels: String::new(),
            envelope: crate::DEFAULT_ENVELOPE.into(),
            limit: String::new(),
            request_concurrency: "1".into(),
        }
    }
}

impl RunnerFields {
    fn of(form: &[(String, String)]) -> Self {
        let get = |name: &str| field(form, name).unwrap_or("").trim().to_string();
        RunnerFields {
            name: get("name"),
            pool: get("pool"),
            labels: get("labels"),
            envelope: get("envelope"),
            limit: get("limit"),
            request_concurrency: get("request_concurrency"),
        }
    }

    /// The settings, parsed as the CLI parses its flags; checked by [`ops::add_runner`].
    fn settings(&self) -> Result<RunnerSettings, String> {
        let envelope =
            crate::parse_envelope(&self.envelope).map_err(|why| format!("envelope {why}"))?;
        let whole = |what: &str, v: &str| {
            v.parse::<u32>()
                .map_err(|_| format!("{what}: expected a whole number"))
        };
        let limit = match self.limit.as_str() {
            "" => None,
            v => Some(whole("limit", v)?),
        };
        Ok(RunnerSettings {
            placement: Placement {
                pool: self.pool.clone(),
                labels: (self.labels.split(','))
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect(),
                envelope,
            },
            limit,
            request_concurrency: whole("request concurrency", &self.request_concurrency)?,
        })
    }
}

/// `GET /relay/<id>/add-runner`: an operator's form adding a runner to the relay.
pub(super) async fn add_runner_page(id: &str, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    if auth.session.role < Role::Operator {
        return Ok(super::message(
            StatusCode::FORBIDDEN,
            "Only operators add runners.",
        ));
    }
    let (hub, wanted) = (ui.hub.clone(), id.to_string());
    let Some(relay) = blocking(move || ops::detail(&hub, &wanted)).await? else {
        return Ok(super::message(
            StatusCode::NOT_FOUND,
            "There is no such relay.",
        ));
    };
    Ok(runner_form(
        StatusCode::OK,
        auth,
        &relay,
        &RunnerFields::default(),
        None,
    ))
}

/// The add-runner page for `relay`, filled in with `fields`, saying why `refused` if it was.
/// A relay that takes no runner gets why, and no form.
fn runner_form(
    status: StatusCode,
    auth: &Auth,
    relay: &RelayView,
    fields: &RunnerFields,
    refused: Option<&str>,
) -> Response<Body> {
    let mut h = Html::new();
    h.raw("<h1>Add a runner</h1><p class=\"sub\">Relay <strong>")
        .node(&relay.row.hostname)
        .raw("</strong> <code>")
        .text(crate::rollout::short_id(&relay.id))
        .raw("</code></p>");
    if let Some(why) = refused {
        h.raw("<p class=\"message\">Refused: ")
            .text(why)
            .raw(".</p>");
    }
    if let Some(why) = ops::runners_refusal(&relay.row) {
        h.raw("<p class=\"message\">")
            .text(capitalized(&vk_hub_proto::display_safe(&why)))
            .raw(".</p>");
    } else {
        h.raw("<section><form class=\"wide\" method=\"post\" action=\"")
            .raw(PREFIX)
            .text(&relay.id)
            .raw("/action\">");
        csrf_field(&mut h, auth);
        h.raw("<input type=\"hidden\" name=\"op\" value=\"")
            .raw(ADD_RUNNER)
            .raw("\"><label for=\"runner-token\">Token</label>")
            .raw("<input id=\"runner-token\" type=\"password\" name=\"token\" ")
            .raw("autocomplete=\"off\" spellcheck=\"false\" required placeholder=\"glrt-…\">");
        input(&mut h, "Name", "name", &fields.name, "ci-1");
        input(&mut h, "Pool", "pool", &fields.pool, "default");
        input(
            &mut h,
            "Labels",
            "labels",
            &fields.labels,
            "none, or kvm, big",
        );
        input(
            &mut h,
            "Envelope",
            "envelope",
            &fields.envelope,
            crate::DEFAULT_ENVELOPE,
        );
        input(&mut h, "Limit", "limit", &fields.limit, "no limit");
        input(
            &mut h,
            "Request concurrency",
            "request_concurrency",
            &fields.request_concurrency,
            "1",
        );
        h.raw("<button class=\"primary\">Add runner</button></form>")
            .raw("<p class=\"sub\">Create the runner in GitLab first, then paste its token ")
            .raw("(<code>glrt-…</code>). The name is letters, digits, <code>-</code>, ")
            .raw("<code>_</code> and <code>.</code>. Separate labels with commas. The envelope ")
            .raw("is each job's VM: <code>mem=&lt;size&gt;,cpus=&lt;n&gt;,disk=&lt;size&gt;")
            .raw("</code>. The limit caps its jobs running at once. Its jobs run once a lane ")
            .raw("maps the runner on <a href=\"")
            .raw(super::lanes::PATH)
            .raw("\">Lanes</a>.</p></section>");
    }
    h.raw("<p><a href=\"")
        .text(back(relay))
        .raw("\">Back to GitLab</a></p>");
    let mut resp = page(fleet::layout(
        "Add a runner",
        super::clients::GITLAB_PATH,
        auth,
        &h,
    ));
    *resp.status_mut() = status;
    resp
}

/// A text field of the add-runner form, `name` holding `value`.
fn input(h: &mut Html, label: &'static str, name: &'static str, value: &str, hint: &'static str) {
    h.raw("<label for=\"runner-")
        .raw(name)
        .raw("\">")
        .raw(label)
        .raw("</label><input id=\"runner-")
        .raw(name)
        .raw("\" type=\"text\" name=\"")
        .raw(name)
        .raw("\" autocomplete=\"off\" spellcheck=\"false\" value=\"")
        .text(value)
        .raw("\" placeholder=\"")
        .raw(hint)
        .raw("\">");
}

/// Where a page about `relay`'s runners leads back to: the relay on its server's page, else
/// GitLab's Overview.
fn back(relay: &RelayView) -> String {
    super::clients::relay_page(relay).unwrap_or_else(|| super::clients::GITLAB_PATH.to_string())
}

/// `s` with its first letter capitalized.
fn capitalized(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

/// Add the runner `form` asks for to relay `id`, as `vk-hub relays runners add` does, then back
/// to the relay on its server's page, which shows how it ends. A refusal shows the form again,
/// but not the token.
async fn add_runner(
    ui: &Ui,
    auth: &Auth,
    form: &[(String, String)],
    id: &str,
) -> Result<Response<Body>> {
    let fields = RunnerFields::of(form);
    let token = RunnerToken::new(field(form, "token").unwrap_or("").trim());
    let (hub, wanted) = (ui.hub.clone(), id.to_string());
    let Some(relay) = blocking(move || ops::detail(&hub, &wanted)).await? else {
        return Ok(super::message(
            StatusCode::NOT_FOUND,
            "There is no such relay.",
        ));
    };
    let settings = match fields.settings() {
        Ok(settings) => settings,
        Err(why) => {
            return Ok(runner_form(
                StatusCode::BAD_REQUEST,
                auth,
                &relay,
                &fields,
                Some(&why),
            ));
        }
    };
    let (hub, principal, wanted, name) = (
        ui.hub.clone(),
        auth.session.principal(),
        id.to_string(),
        fields.name.clone(),
    );
    let issued = blocking(move || {
        Ok(ops::add_runner(
            &hub, &principal, &wanted, &name, token, settings,
        ))
    })
    .await?;
    match issued {
        Ok(command) => {
            eprintln!(
                "vk-hub: ui: {} added runner {} to relay {id} (command {})",
                auth.session.principal(),
                fields.name,
                command.id
            );
            Ok(super::clients::see_other(&back(&relay)))
        }
        Err(e) if e.is::<NotEnrolled>() => Ok(super::message(
            StatusCode::NOT_FOUND,
            "There is no such relay.",
        )),
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            Ok(runner_form(
                StatusCode::CONFLICT,
                auth,
                &relay,
                &fields,
                Some(&said),
            ))
        }
    }
}

/// Remove the runner `form` names from relay `id` once confirmed, as `vk-hub relays runners
/// remove` does.
async fn remove_runner(
    ui: &Ui,
    site: &FleetSite,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    id: &str,
) -> Result<Response<Body>> {
    let name = field(form, "name").unwrap_or("").to_string();
    let (hub, wanted) = (ui.hub.clone(), id.to_string());
    let Some(relay) = blocking(move || ops::detail(&hub, &wanted)).await? else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such relay.",
        ));
    };
    let runner = (relay.row.inventory.iter())
        .flat_map(|i| &i.runners)
        .find(|r| r.name == name);
    let Some(runner) = runner else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "The relay has no such runner.",
        ));
    };
    let mut detail = Html::new();
    detail
        .raw("<p>Runner <strong>")
        .node(&runner.name)
        .raw("</strong>");
    if let Some(gitlab_id) = runner.runner_id {
        detail.raw(" (GitLab ID ").text(gitlab_id).raw(")");
    }
    detail
        .raw(" on relay <strong>")
        .node(&relay.row.hostname)
        .raw("</strong></p>");
    let ask = actions::Ask {
        path: format!("{PREFIX}{id}/action"),
        back: back(&relay),
        op: REMOVE_RUNNER.to_string(),
        what: "Remove this runner? It stops taking new jobs and is removed after its running \
               jobs end. It stays in GitLab; delete it there.",
        detail,
        asked: vec![
            ("name", name.clone()),
            ("command", runner.command.clone().unwrap_or_default()),
        ],
    };
    if let Some(asked) = actions::ask_first(&site.questions, fleet::layout, htmx, auth, form, &ask)?
    {
        return Ok(asked);
    }
    let (hub, principal, wanted, named) = (
        ui.hub.clone(),
        auth.session.principal(),
        id.to_string(),
        name.clone(),
    );
    let added_by = runner.command.clone().unwrap_or_default();
    let issued = blocking(move || {
        Ok(ops::remove_runner(
            &hub,
            &principal,
            &wanted,
            &named,
            Some(&added_by),
        ))
    })
    .await?;
    match issued {
        Ok(command) => {
            eprintln!(
                "vk-hub: ui: {} removed runner {name} from relay {id} (command {})",
                auth.session.principal(),
                command.id
            );
            if !htmx {
                return Ok(super::clients::see_other(&back(&relay)));
            }
            Ok(fleet::said_so(&format!(
                "Removing runner {} from {}. It goes once its running jobs end.",
                vk_hub_proto::display_safe(&name),
                vk_hub_proto::display_safe(&relay.row.hostname),
            )))
        }
        Err(e) if e.is::<NotEnrolled>() => Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such relay.",
        )),
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {said}."),
            ))
        }
    }
}

/// A button posting the removal of runner `name` from relay `id`, asked first. No CSRF field:
/// the page around the fragment sets the token as a header.
pub(super) fn remove_runner_button(h: &mut Html, id: &str, name: &str) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PREFIX)
        .text(id)
        .raw("/action\" hx-post=\"")
        .raw(PREFIX)
        .text(id)
        .raw("/action\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
        .raw(REMOVE_RUNNER)
        .raw("\"><input type=\"hidden\" name=\"name\" value=\"")
        .text(name)
        .raw("\"><button class=\"danger\">Remove</button></form>");
}

/// Where runner `origin` comes from, as a runner's row says it.
pub(super) fn origin_text(origin: RunnerOrigin<'_>) -> &'static str {
    match origin {
        RunnerOrigin::Config => "config",
        RunnerOrigin::Hub { removing: true, .. } => "being removed",
        RunnerOrigin::Hub { .. } => "added on the hub",
        RunnerOrigin::Other => "other",
    }
}

/// How runner command `c` ended, or that it has not yet, as of `now`: `None` while pending,
/// else whether it is done or why it failed.
pub(super) fn runner_command_state(
    c: &RelayCommandRow,
    now: u64,
) -> Option<Result<(), &'static str>> {
    let failure = match &c.outcome {
        None if c.command.expires_at > now => return None,
        Some(Outcome::Accepted) => return None,
        Some(Outcome::Done) => return Some(Ok(())),
        None => RunnerFailure::Expired,
        Some(outcome) => RunnerFailure::of(outcome).unwrap_or(RunnerFailure::Other),
    };
    Some(Err(failure_text(failure)))
}

/// What a runner command's failure means to whoever sent it.
fn failure_text(f: RunnerFailure) -> &'static str {
    match f {
        RunnerFailure::TokenRefused => "GitLab refused the token",
        RunnerFailure::GitlabUnreachable => {
            "The relay could not reach GitLab: add the runner again"
        }
        RunnerFailure::NameTaken => "The relay has a runner with this name already",
        RunnerFailure::RunnerTaken => {
            "The relay runs this GitLab runner already, under another name"
        }
        RunnerFailure::TooManyRunners => "The relay runs as many runners as it can",
        RunnerFailure::NotAllowed => "The relay's [hub] allow no longer lists runners",
        RunnerFailure::Expired => "The relay did not take it in time",
        RunnerFailure::RunnerGone => "The relay no longer runs this runner",
        RunnerFailure::TokenLost => {
            "The hub restarted before the relay got the token: add the runner again"
        }
        RunnerFailure::Other => "The relay could not do it: see its log",
    }
}

/// What runner command `c` is: adding or removing its runner, and the runner's name.
pub(super) fn runner_command_what(c: &RelayCommandRow) -> Option<(&'static str, &str)> {
    match &c.command.op {
        Operation::AddRunner { name, .. } => Some(("Add runner", name)),
        Operation::RemoveRunner { name, .. } => Some(("Remove runner", name)),
        Operation::Update { .. } => None,
    }
}
