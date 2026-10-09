//! Operator actions on this machine's VMs use the same `vk` commands as a shell: stop or
//! reboot a pinned run (`vk stop`, `vk reboot`), stop a dev environment (`vk dev stop`),
//! restart it in its workspace (`vk dev up`), or remove it once stale (`vk dev gc`).
//! CI jobs remain under their runner's control.
//!
//! Every action is a `POST` the UI's checks pass ([`super::check_post`]), done as the
//! session's principal and recorded in the audit log before it runs and as it ends. One that
//! cannot be taken back — a stop, a reboot, a removal — is asked again first, on a form of its
//! own: the policy allows no `confirm()`. The question is answered once, by the session it
//! was asked of, and only while what it was asked about is as it was — the same `vk run` for
//! a VM, the same boot for a dev environment. The command runs in the background, one at a
//! time on each thing acted on, and the pages show it under way and how it ended.
//!
//! A start runs `vk dev up` in the workspace and environment `vk dev list` records, which
//! reads the workspace's own config: `vk dev list` records no `--dev-config`, so an
//! environment booted from a config kept elsewhere is started again from a shell.

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::{Workload, WorkloadKind};

use super::dev::{DevRow, dev_name};
use super::html::Html;
use super::local::{self, LocalSite};
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui};
use crate::local::{Action, NotStarted};
use crate::store::Role;

/// How long a stop or a reboot may take: `vk stop` waits up to 90 seconds itself.
const STOP_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long `vk dev up` may take: it may build the environment's images first.
const UP_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// How long a question stays answerable.
const QUESTION_LIFE: Duration = Duration::from_secs(10 * 60);

/// The most questions kept unanswered; the oldest goes first.
const MAX_QUESTIONS: usize = 1024;

/// What an action on `w` is keyed by: a dev environment's name, which `/dev` acts on too, or
/// the VM's ID.
pub(super) fn key(w: &Workload) -> String {
    match (w.kind, dev_name(w)) {
        (WorkloadKind::Dev, Some(name)) => dev_key(&name),
        _ => format!("vm/{}", w.id),
    }
}

pub(super) fn dev_key(name: &str) -> String {
    format!("dev/{name}")
}

/// The actions a VM's page offers, as `(op, label)`: those [`vm_command`] has a command for.
pub(super) fn vm_ops(w: &Workload) -> Vec<(&'static str, &'static str)> {
    [("stop", "Stop"), ("reboot", "Reboot")]
        .into_iter()
        .filter(|(op, _)| vm_command(w, op).is_some())
        .collect()
}

/// The `vk` arguments for `op` on `w`. A run is named by the pid of its `vk run` where the
/// list has it — `vk stop <dir>` also stops the VMs of every directory below that one — and
/// otherwise by its state dir, if the list shows that as it is.
fn vm_command(w: &Workload, op: &str) -> Option<Vec<OsString>> {
    let target = || match w.pid {
        Some(pid) => Some(OsString::from(pid.to_string())),
        None => super::local::exact_state_dir(w).map(OsString::from),
    };
    match (w.kind, op) {
        (WorkloadKind::Run, "stop") => Some(vec!["stop".into(), "--".into(), target()?]),
        (WorkloadKind::Run, "reboot") => Some(vec!["reboot".into(), "--".into(), target()?]),
        (WorkloadKind::Dev, "stop") => Some(vec![
            "dev".into(),
            "stop".into(),
            "--".into(),
            dev_name(w)?.into(),
        ]),
        _ => None,
    }
}

/// What the VM is, in the audit log.
fn vm_about(w: &Workload) -> String {
    format!("VM {} ({})", w.id, w.state_dir)
}

/// `POST /vm/<id>/action`.
pub(super) async fn vm_action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &LocalSite,
    id: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(refused(htmx, status, text)),
    };
    let Some((w, _)) = site.local.workload(id) else {
        return Ok(refused(
            htmx,
            StatusCode::NOT_FOUND,
            "No such VM is running on this machine.",
        ));
    };
    let op = super::field(&form, "op").unwrap_or("");
    let Some(args) = vm_command(&w, op) else {
        return Ok(refused(htmx, StatusCode::BAD_REQUEST, "No such action."));
    };
    let back = format!("/vm/{id}");
    let ask = Ask {
        path: format!("{back}/action"),
        back: back.clone(),
        op: op.to_string(),
        what: match (w.kind, op) {
            (_, "reboot") => "Reboot this VM? Its guest restarts on the same disks.",
            (WorkloadKind::Dev, _) => {
                "Stop this environment? Its guest powers off; its state stays for the next \
                 start."
            }
            _ => "Stop this VM? Its guest powers off, and it is gone until run again.",
        },
        detail: Html::new(),
        // The `vk run` it was asked about: its pid, and when it started, which tells two
        // apart where the list has no pid.
        asked: vec![("pid", or_dash(w.pid)), ("started", or_dash(w.started_at))],
    };
    if let Some(asked) = ask_first(&site.questions, local::layout, htmx, &auth, &form, &ask)? {
        return Ok(asked);
    }
    let act = Act {
        key: key(&w),
        about: vm_about(&w),
        args,
        timeout: STOP_TIMEOUT,
    };
    run(ui, site, htmx, &auth, act, &back, true).await
}

/// The actions `/dev` offers `row`, as `(op, label)`.
pub(super) fn dev_ops(row: &DevRow) -> Vec<(&'static str, &'static str)> {
    let mut ops = Vec::new();
    if row.running() {
        ops.push(("stop", "Stop"));
    } else if row.workspace.is_some() && row.environment.is_some() && !row.has("workspace-missing")
    {
        ops.push(("start", "Start"));
    }
    if row.stale() {
        ops.push(("gc", "Remove"));
    }
    ops
}

/// The `vk` arguments for `op` on `row`, and how long they may take.
fn dev_command(row: &DevRow, op: &str) -> Option<(Vec<OsString>, Duration)> {
    if !dev_ops(row).iter().any(|(o, _)| *o == op) {
        return None;
    }
    Some(match op {
        "stop" => (
            vec![
                "dev".into(),
                "stop".into(),
                "--".into(),
                row.name.clone().into(),
            ],
            STOP_TIMEOUT,
        ),
        "start" => (
            vec![
                "dev".into(),
                "up".into(),
                // Joined, so a value starting with `-` is never taken for an option.
                format!("--workspace={}", row.workspace.as_deref()?).into(),
                format!("--environment={}", row.environment.as_deref()?).into(),
            ],
            UP_TIMEOUT,
        ),
        "gc" => (
            vec![
                "dev".into(),
                "gc".into(),
                "--yes".into(),
                "--".into(),
                row.name.clone().into(),
            ],
            STOP_TIMEOUT,
        ),
        _ => return None,
    })
}

/// `POST /dev/<name>/action`.
pub(super) async fn dev_action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &LocalSite,
    name: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(refused(htmx, status, text)),
    };
    let op = super::field(&form, "op").unwrap_or("").to_string();
    // Read again, so a start goes to its recorded workspace and a removal only to one that is
    // still stale.
    let rows = site
        .dev_list
        .get(&site.local, &ui.hub, Duration::ZERO)
        .await;
    let row = match &*rows {
        Ok(rows) => rows.iter().find(|r| r.name == name),
        Err(why) => {
            eprintln!("vk-hub: ui: {why}");
            return Ok(refused(
                htmx,
                StatusCode::INTERNAL_SERVER_ERROR,
                "`vk dev list` failed; the hub's log says how.",
            ));
        }
    };
    let Some(row) = row else {
        return Ok(refused(
            htmx,
            StatusCode::NOT_FOUND,
            "This host keeps no such dev environment.",
        ));
    };
    let Some((args, timeout)) = dev_command(row, &op) else {
        return Ok(refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "Not an action this environment takes as it stands.",
        ));
    };
    if op != "start" {
        let ask = Ask {
            path: format!("/dev/{name}/action"),
            back: "/dev".to_string(),
            what: match op.as_str() {
                "gc" => {
                    "Remove this environment's state — its storage, keys and identity? It is \
                     not running, and this cannot be undone."
                }
                _ => {
                    "Stop this environment? Its guest powers off; its state stays for the next \
                     start."
                }
            },
            op,
            detail: Html::new(),
            // The boot it was asked about.
            asked: vec![("booted", or_dash(row.booted_secs))],
        };
        if let Some(asked) = ask_first(&site.questions, local::layout, htmx, &auth, &form, &ask)? {
            return Ok(asked);
        }
    }
    let act = Act {
        key: dev_key(name),
        about: format!("dev environment {name}"),
        args,
        timeout,
    };
    run(ui, site, htmx, &auth, act, "/dev", false).await
}

/// A figure as a question's hidden field carries it: `-` for none.
fn or_dash(n: Option<impl std::fmt::Display>) -> String {
    n.map_or_else(|| "-".to_string(), |n| n.to_string())
}

/// What an action runs, and on what.
struct Act {
    /// What it is one at a time on, and shown under.
    key: String,
    /// What it acts on, in the audit log.
    about: String,
    args: Vec<OsString>,
    timeout: Duration,
}

/// Start `act` as the session's action, and answer: for htmx, a line saying it started,
/// swapped into the flash; else back to `back`, which shows how it ends as it does if `live`,
/// and once reloaded otherwise.
async fn run(
    ui: &Ui,
    site: &LocalSite,
    htmx: bool,
    auth: &Auth,
    act: Act,
    back: &str,
    live: bool,
) -> Result<Response<Body>> {
    let principal = auth.session.principal();
    let started = site
        .local
        .start(
            &ui.hub,
            &act.key,
            act.about,
            act.args,
            act.timeout,
            &principal,
        )
        .await;
    let command = match started {
        Ok(command) => command,
        Err(NotStarted::Busy) => {
            return Ok(refused(
                htmx,
                StatusCode::CONFLICT,
                "Refused: something is already being done to it; wait for that to end.",
            ));
        }
        Err(NotStarted::Unaudited) => {
            return Ok(refused(
                htmx,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Refused: the audit log could not be written, so nothing was run; the hub's log \
                 says why.",
            ));
        }
    };
    eprintln!("vk-hub: ui: {principal} ran `{command}`");
    if !htmx {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::SEE_OTHER;
        resp.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_str(back)?);
        return Ok(resp);
    }
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">Started <code>")
        .node(&command)
        .raw(if live {
            "</code>; how it ends shows below and in the audit log.</div>"
        } else {
            "</code>; reload the page for how it ends, which the audit log records too.</div>"
        });
    Ok(swap_none(super::html_response(StatusCode::OK, h)))
}

/// The questions asked and not yet answered, by the nonce each one's form carries.
pub(super) struct Questions(Mutex<HashMap<String, Question>>);

struct Question {
    /// The CSRF token of the session it was asked of.
    session: String,
    path: String,
    op: String,
    /// What it was asked about, as its form's hidden fields have it.
    asked: Asked,
    at: Instant,
}

/// What a question is asked about, as `(field, value)`: what must be as it was for its answer
/// to count.
pub(super) type Asked = Vec<(&'static str, String)>;

/// A question an action asks first.
pub(super) struct Ask {
    /// The action's path, which the answer posts to.
    pub(super) path: String,
    /// The page it is asked from.
    pub(super) back: String,
    pub(super) op: String,
    pub(super) what: &'static str,
    /// What it would do, in detail, shown below the question.
    pub(super) detail: Html,
    pub(super) asked: Asked,
}

impl Questions {
    pub(super) fn new() -> Self {
        Questions(Mutex::new(HashMap::new()))
    }

    /// Keep `q`, and return the nonce its form answers it by.
    fn ask(&self, q: Question) -> Result<String> {
        let nonce = crate::random_hex(16)?;
        let mut kept = self.lock();
        kept.retain(|_, q| q.at.elapsed() < QUESTION_LIFE);
        if kept.len() >= MAX_QUESTIONS
            && let Some(oldest) = kept
                .iter()
                .min_by_key(|(_, q)| q.at)
                .map(|(n, _)| n.clone())
        {
            kept.remove(&oldest);
        }
        kept.insert(nonce.clone(), q);
        Ok(nonce)
    }

    /// The question `nonce` answers, if it was asked of `session` for `op` on `path` and has
    /// not expired: taken, so it is answered once. One asked of another is left to it.
    fn answer(&self, nonce: &str, session: &str, path: &str, op: &str) -> Option<Question> {
        let mut kept = self.lock();
        let q = kept.get(nonce)?;
        if q.at.elapsed() >= QUESTION_LIFE {
            kept.remove(nonce);
            return None;
        }
        if q.session != session || q.path != path || q.op != op {
            return None;
        }
        kept.remove(nonce)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Question>> {
        // Entries replaced whole: nothing half-written for a panic to leave behind.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Confirm an irreversible action. Return `None` when `form` answers `ask`, otherwise the
/// question or a refusal. Plain forms show the question in a page built with `layout`.
pub(super) fn ask_first(
    questions: &Questions,
    layout: Layout,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    ask: &Ask,
) -> Result<Option<Response<Body>>> {
    if super::field(form, "confirm") != Some("yes") {
        return confirm(questions, layout, htmx, auth, ask).map(Some);
    }
    Ok(answered(questions, auth, form, ask)
        .err()
        .map(|why| refused(htmx, StatusCode::CONFLICT, why)))
}

/// Wrap a page's main content in the site's layout, as [`super::local::layout`].
pub(super) type Layout = fn(&str, &str, &Auth, &Html) -> Html;

/// Whether `form` answers `ask`, asked of this session, with what it was asked about as it is
/// now.
fn answered(
    questions: &Questions,
    auth: &Auth,
    form: &[(String, String)],
    ask: &Ask,
) -> Result<(), &'static str> {
    let q = super::field(form, "nonce")
        .and_then(|nonce| questions.answer(nonce, &auth.csrf, &ask.path, &ask.op))
        .ok_or("Refused: this was answered already, or asked too long ago; ask again.")?;
    let posted = ask
        .asked
        .iter()
        .all(|(field, value)| super::field(form, field) == Some(value.as_str()));
    if q.asked != ask.asked || !posted {
        return Err("Refused: it changed since you were asked; look again.");
    }
    Ok(())
}

/// The question an action that cannot be taken back asks first, in the flash's place — or,
/// for a plain form, as a page of its own — with a form that answers it once.
fn confirm(
    questions: &Questions,
    layout: Layout,
    htmx: bool,
    auth: &Auth,
    ask: &Ask,
) -> Result<Response<Body>> {
    let nonce = questions.ask(Question {
        session: auth.csrf.clone(),
        path: ask.path.clone(),
        op: ask.op.clone(),
        asked: ask.asked.clone(),
        at: Instant::now(),
    })?;
    let mut form = Html::new();
    form.raw("<form method=\"post\" action=\"")
        .text(&ask.path)
        .raw("\" hx-post=\"")
        .text(&ask.path)
        .raw("\" hx-swap=\"none\">");
    csrf_field(&mut form, auth);
    form.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .text(&ask.op)
        .raw("\">");
    for (field, value) in &ask.asked {
        form.raw("<input type=\"hidden\" name=\"")
            .raw(field)
            .raw("\" value=\"")
            .text(value)
            .raw("\">");
    }
    form.raw("<input type=\"hidden\" name=\"nonce\" value=\"")
        .text(&nonce)
        .raw("\"><input type=\"hidden\" name=\"confirm\" value=\"yes\">")
        .raw("<button class=\"danger\">Yes, ")
        .text(&ask.op)
        .raw("</button></form>");
    if htmx {
        let mut h = Html::new();
        h.raw("<div id=\"flash\" hx-swap-oob=\"true\" class=\"error\">")
            .raw(ask.what)
            .raw(" ")
            .html(&ask.detail)
            .html(&form)
            .raw("</div>");
        return Ok(swap_none(super::html_response(StatusCode::OK, h)));
    }
    // `back` is the hub's own path, built from checked IDs and names.
    let mut main = Html::new();
    main.raw("<h1>Confirm</h1><p>")
        .raw(ask.what)
        .raw("</p>")
        .html(&ask.detail)
        .html(&form)
        .raw("<p><a href=\"")
        .text(&ask.back)
        .raw("\">Cancel</a></p>");
    Ok(super::page(layout("Confirm", &ask.back, auth, &main)))
}

/// A refused action: for htmx, the line saying why, swapped in on its own.
pub(super) fn refused(htmx: bool, status: StatusCode, text: &str) -> Response<Body> {
    if !htmx {
        return super::message(status, text);
    }
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\" class=\"error\">")
        .text(text)
        .raw("</div>");
    swap_none(super::html_response(status, h))
}

/// `resp` swapped out of band only: the page around the flash stays as it is.
pub(super) fn swap_none(mut resp: Response<Body>) -> Response<Body> {
    resp.headers_mut()
        .insert("hx-reswap", HeaderValue::from_static("none"));
    resp
}

/// A form posting `op` to `path`, by htmx or as a plain form. `path` is the hub's, built from
/// checked IDs and names.
pub(super) fn op_form(
    h: &mut Html,
    auth: &Auth,
    path: &str,
    op: &'static str,
    label: &'static str,
) {
    h.raw("<form method=\"post\" action=\"")
        .text(path)
        .raw("\" hx-post=\"")
        .text(path)
        .raw("\" hx-swap=\"none\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .raw(op)
        .raw("\"><button>")
        .raw(label)
        .raw("</button></form>");
}

/// The last action on something, in a line: who ran it, and that it is under way or how and
/// when it ended.
pub(super) fn action_line(h: &mut Html, action: Option<&Action>) {
    let Some(a) = action else {
        h.raw("-");
        return;
    };
    h.raw("<code>")
        .node(&a.command)
        .raw("</code> by ")
        .text(&a.by)
        .raw(", ");
    match &a.ended {
        None => {
            h.raw("running since ").html(&pages::at_html(a.started_at));
        }
        Some(e) => {
            h.raw(if e.ok {
                "succeeded"
            } else {
                "<span class=\"reason\">failed</span>"
            })
            .raw(", ended ")
            .html(&pages::at_html(e.at))
            .raw(": ")
            .node(&e.said);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::dev::tests::{dev_workload, row};
    use super::*;

    #[test]
    fn an_environment_is_offered_what_it_can_take() {
        let ops = |r: &DevRow| dev_ops(r).into_iter().map(|(o, _)| o).collect::<Vec<_>>();
        assert_eq!(ops(&row("running", &[])), ["stop"]);
        assert_eq!(ops(&row("running", &["workspace-missing"])), ["stop"]);
        assert_eq!(ops(&row("stopped", &[])), ["start"]);
        // Its workspace gone: nothing to start it in.
        assert_eq!(ops(&row("stopped", &["workspace-missing"])), ["gc"]);
        assert!(ops(&row("stopped", &["pinned"])) == ["start"]);
        let mut bare = row("never-booted", &["ephemeral"]);
        bare.workspace = None;
        assert_eq!(ops(&bare), ["gc"]);
        let (args, _) = dev_command(&row("stopped", &[]), "start").unwrap();
        assert_eq!(
            args,
            ["dev", "up", "--workspace=/src/app", "--environment=dev"].map(OsString::from)
        );
        // A value that starts with `-` stays joined to its option.
        let mut dashed = row("stopped", &[]);
        dashed.workspace = Some("-rf".into());
        dashed.environment = Some("--yes".into());
        let (args, _) = dev_command(&dashed, "start").unwrap();
        assert_eq!(
            args,
            ["dev", "up", "--workspace=-rf", "--environment=--yes"].map(OsString::from)
        );
        assert!(dev_command(&row("stopped", &[]), "gc").is_none());
        assert!(dev_command(&row("running", &[]), "start").is_none());
    }

    #[test]
    fn a_vm_is_offered_what_it_has_a_command_for() {
        let mut w = dev_workload();
        assert_eq!(key(&w), "dev/app-1234");
        assert_eq!(vm_ops(&w), [("stop", "Stop")]);
        assert_eq!(
            vm_command(&w, "stop").unwrap(),
            ["dev", "stop", "--", "app-1234"].map(OsString::from)
        );
        assert!(vm_command(&w, "reboot").is_none());
        // A dev environment whose state dir the list shows altered: no name to stop it by,
        // and keyed by its ID.
        w.state_dir = "/s/app-12\u{fffd}34".into();
        assert!(vm_ops(&w).is_empty() && vm_command(&w, "stop").is_none());
        assert_eq!(key(&w), format!("vm/{}", w.id));
        w.kind = WorkloadKind::Run;
        // Its run is still named by its pid.
        assert_eq!(vm_ops(&w), [("stop", "Stop"), ("reboot", "Reboot")]);
        assert_eq!(
            vm_command(&w, "reboot").unwrap(),
            ["reboot", "--", "7"].map(OsString::from)
        );
        w.pid = None;
        // Named by its state dir only when the list shows it as it is.
        assert!(vm_ops(&w).is_empty());
        w.state_dir = "/s/app-1234".into();
        assert_eq!(
            vm_command(&w, "stop").unwrap(),
            ["stop", "--", "/s/app-1234"].map(OsString::from)
        );
        assert_eq!(key(&w), format!("vm/{}", w.id));
        w.kind = WorkloadKind::CiJob;
        assert!(vm_ops(&w).is_empty() && vm_command(&w, "stop").is_none());
    }

    fn question(session: &str, at: Instant) -> Question {
        Question {
            session: session.into(),
            path: "/vm/x/action".into(),
            op: "stop".into(),
            asked: vec![("pid", "7".into())],
            at,
        }
    }

    /// A question is answered once, by the session it was asked of, for what it asked, and
    /// only while it lives; one asked of another session is left to it.
    #[test]
    fn a_question_is_answered_once_and_by_its_own_session() {
        let qs = Questions::new();
        let nonce = qs.ask(question("a", Instant::now())).unwrap();
        assert!(qs.answer(&nonce, "b", "/vm/x/action", "stop").is_none());
        assert!(qs.answer(&nonce, "a", "/vm/y/action", "stop").is_none());
        assert!(qs.answer(&nonce, "a", "/vm/x/action", "reboot").is_none());
        assert!(qs.answer(&nonce, "a", "/vm/x/action", "stop").is_some());
        assert!(qs.answer(&nonce, "a", "/vm/x/action", "stop").is_none());
        let Some(long_ago) = Instant::now().checked_sub(QUESTION_LIFE) else {
            return;
        };
        let nonce = qs.ask(question("a", long_ago)).unwrap();
        assert!(qs.answer(&nonce, "a", "/vm/x/action", "stop").is_none());
        assert!(qs.lock().is_empty());
    }

    /// Past [`MAX_QUESTIONS`], the oldest question goes first.
    #[test]
    fn the_oldest_question_goes_first() {
        let qs = Questions::new();
        let earlier = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let first = qs.ask(question("old", earlier)).unwrap();
        let rest: Vec<String> = (0..MAX_QUESTIONS)
            .map(|_| qs.ask(question("a", Instant::now())).unwrap())
            .collect();
        assert_eq!(qs.lock().len(), MAX_QUESTIONS);
        assert!(qs.answer(&first, "old", "/vm/x/action", "stop").is_none());
        assert!(qs.answer(&rest[0], "a", "/vm/x/action", "stop").is_some());
    }
}
