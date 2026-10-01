//! What an operator does to this machine's VMs from the UI, each by running the `vk` command
//! a shell would: a pinned run is stopped (`vk stop`) or rebooted (`vk reboot`), a dev
//! environment stopped (`vk dev stop`), started again in its workspace (`vk dev up`), or, once
//! stale, removed (`vk dev gc`). A CI job is its runner's, and is left alone.
//!
//! Every action is a `POST` the UI's checks pass ([`super::check_post`]), done as the
//! session's principal and recorded in the audit log as it starts and as it ends. One that
//! cannot be taken back — a stop, a reboot, a removal — is asked again first, on a form of its
//! own: the policy allows no `confirm()`, and a second post is as plain as the first. The
//! command runs in the background, one at a time on each thing acted on, and the pages show it
//! under way and how it ended.
//!
//! `/dev` lists every dev environment the host keeps state for, as `vk dev list` does —
//! stopped ones too, which `vk workloads` leaves out — and is read as the page loads.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use vk_fleet_proto::{Workload, WorkloadKind};

use super::html::Html;
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, refused};
use crate::local::{Action, Local};
use crate::store::Role;

/// How long a stop or a reboot may take: `vk stop` waits up to 90 seconds itself.
const STOP_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long `vk dev up` may take: it may build the environment's images first.
const UP_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// How long `vk dev list` may take, a page waiting on it.
const LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether `name` is a dev environment's name as `vk dev list` gives one: its state dir's
/// own name. Checked before it is passed to `vk`, or put in a path.
pub(super) fn valid_dev_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// What an action on `w` is keyed by: a dev environment's name, which `/dev` acts on too, or
/// the VM's state dir.
pub(super) fn key(w: &Workload) -> String {
    match (w.kind, dev_name(w)) {
        (WorkloadKind::Dev, Some(name)) => dev_key(&name),
        _ => w.state_dir.clone(),
    }
}

fn dev_key(name: &str) -> String {
    format!("dev/{name}")
}

/// A dev environment's name: its state dir's.
fn dev_name(w: &Workload) -> Option<String> {
    let name = Path::new(&w.state_dir).file_name()?.to_str()?;
    valid_dev_name(name).then(|| name.to_string())
}

/// The actions a VM's page offers, by its kind, as `(op, label)`.
pub(super) fn vm_ops(w: &Workload) -> &'static [(&'static str, &'static str)] {
    match w.kind {
        WorkloadKind::Run => &[("stop", "stop"), ("reboot", "reboot")],
        WorkloadKind::Dev if dev_name(w).is_some() => &[("stop", "stop")],
        _ => &[],
    }
}

/// The `vk` arguments for `op` on `w`. A run is named by the pid of its `vk run` where the
/// list has it — `vk stop <dir>` also stops the VMs of every directory below that one.
fn vm_command(w: &Workload, op: &str) -> Option<Vec<OsString>> {
    let target = || match w.pid {
        Some(pid) => OsString::from(pid.to_string()),
        None => OsString::from(&w.state_dir),
    };
    match (w.kind, op) {
        (WorkloadKind::Run, "stop") => Some(vec!["stop".into(), target()]),
        (WorkloadKind::Run, "reboot") => Some(vec!["reboot".into(), target()]),
        (WorkloadKind::Dev, "stop") => Some(vec!["dev".into(), "stop".into(), dev_name(w)?.into()]),
        _ => None,
    }
}

/// `POST /vm/<id>/action`.
pub(super) async fn vm_action(
    req: Request<Incoming>,
    ui: &Ui,
    local: &Arc<Local>,
    id: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(refused(htmx, status, text)),
    };
    let Some((w, _)) = local.workload(id) else {
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
    if super::field(&form, "confirm") != Some("yes") {
        let what = match op {
            "reboot" => "Reboot this VM? Its guest restarts on the same disks.",
            _ => "Stop this VM? Its guest powers off; a pinned run's VM is gone until run again.",
        };
        return Ok(confirm(htmx, &auth, &format!("{back}/action"), op, what));
    }
    run(
        ui,
        local,
        htmx,
        &auth,
        (&key(&w), args, STOP_TIMEOUT),
        &back,
    )
}

/// One row of `vk dev list --json`: the fields this page reads, whose names are that
/// command's interface and are only ever added to.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct DevRow {
    pub name: String,
    pub workspace: Option<String>,
    pub environment: Option<String>,
    pub status: String,
    #[serde(default)]
    pub booted_secs: Option<u64>,
    #[serde(default)]
    pub flags: Vec<String>,
}

impl DevRow {
    fn running(&self) -> bool {
        self.status == "running"
    }

    /// Stale, as `vk dev gc --all-stale` takes it: its workspace gone, or no boot recorded.
    fn stale(&self) -> bool {
        !self.running() && !self.flags.is_empty()
    }

    /// The actions `/dev` offers it, as `(op, label)`.
    fn ops(&self) -> Vec<(&'static str, &'static str)> {
        let mut ops = Vec::new();
        if self.running() {
            ops.push(("stop", "stop"));
        } else if self.workspace.is_some() && self.environment.is_some() {
            ops.push(("start", "start"));
        }
        if self.stale() {
            ops.push(("gc", "remove"));
        }
        ops
    }

    /// The `vk` arguments for `op` on it, and how long they may take.
    fn command(&self, op: &str) -> Option<(Vec<OsString>, Duration)> {
        if !self.ops().iter().any(|(o, _)| *o == op) {
            return None;
        }
        Some(match op {
            "stop" => (
                vec!["dev".into(), "stop".into(), self.name.clone().into()],
                STOP_TIMEOUT,
            ),
            "start" => (
                vec![
                    "dev".into(),
                    "up".into(),
                    "--workspace".into(),
                    self.workspace.clone()?.into(),
                    "--environment".into(),
                    self.environment.clone()?.into(),
                ],
                UP_TIMEOUT,
            ),
            "gc" => (
                vec![
                    "dev".into(),
                    "gc".into(),
                    "--yes".into(),
                    self.name.clone().into(),
                ],
                STOP_TIMEOUT,
            ),
            _ => return None,
        })
    }
}

/// Every dev environment this host keeps state for, by `vk dev list`, or why there is none.
async fn dev_rows(local: &Local) -> Result<Vec<DevRow>, String> {
    let out = local
        .run(
            &[
                "dev".as_ref(),
                "list".as_ref(),
                "--json".as_ref(),
                "--no-sizes".as_ref(),
            ],
            LIST_TIMEOUT,
        )
        .await
        .map_err(|e| format!("{e:#}"))?;
    if !out.ok {
        return Err(format!(
            "`vk dev list` {}: {}",
            out.status,
            out.stderr.trim()
        ));
    }
    let rows: Vec<DevRow> = serde_json::from_str(&out.stdout)
        .map_err(|e| format!("`vk dev list` printed something this vk-hub cannot read: {e}"))?;
    Ok(rows
        .into_iter()
        .filter(|r| valid_dev_name(&r.name))
        .collect())
}

/// `GET /dev`.
pub(super) async fn dev_page(auth: &Auth, local: &Local) -> Response<Body> {
    let rows = dev_rows(local).await;
    let mut main = Html::new();
    main.raw("<h1>Dev environments</h1>");
    let steer = auth.session.role >= Role::Operator;
    if steer {
        main.raw("<div id=\"flash\"></div>");
    }
    match rows {
        Err(why) => {
            main.raw("<p class=\"notes\">").node(&why).raw("</p>");
        }
        Ok(rows) if rows.is_empty() => {
            main.raw("<p class=\"empty\">This host keeps no dev environment.</p>");
        }
        Ok(rows) => dev_table(&mut main, &rows, local, steer.then_some(auth)),
    }
    main.raw("<p class=\"sub\">Read as the page loads; <a href=\"/dev\">reload</a> for newer.</p>");
    super::page(super::local::layout("dev environments", auth, &main))
}

fn dev_table(h: &mut Html, rows: &[DevRow], local: &Local, steer: Option<&Auth>) {
    h.raw("<table class=\"grid\"><thead><tr><th>NAME</th><th>STATUS</th><th>WORKSPACE</th>")
        .raw("<th>ENV</th><th>BOOTED</th><th>FLAGS</th><th>LAST ACTION</th>");
    if steer.is_some() {
        h.raw("<th></th>");
    }
    h.raw("</tr></thead><tbody>");
    for r in rows {
        let dash = pages::dash;
        h.raw("<tr><td>")
            .node(&r.name)
            .raw("</td><td>")
            .node(&r.status)
            .raw("</td><td>")
            .node(r.workspace.as_deref().unwrap_or("-"))
            .raw("</td><td>")
            .node(r.environment.as_deref().unwrap_or("-"))
            .raw("</td><td>")
            .text(r.booted_secs.map_or_else(dash, pages::started))
            .raw("</td><td>")
            .node(&r.flags.join(", "))
            .raw("</td><td>");
        action_line(h, local.action(&dev_key(&r.name)).as_ref());
        h.raw("</td>");
        if let Some(auth) = steer {
            h.raw("<td class=\"actions\">");
            for (op, label) in r.ops() {
                // The name is checked as a dev environment's before it is put in a path.
                let path = format!("/dev/{}/action", r.name);
                op_form(h, auth, &path, op, label);
            }
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// `POST /dev/<name>/action`.
pub(super) async fn dev_action(
    req: Request<Incoming>,
    ui: &Ui,
    local: &Arc<Local>,
    name: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(refused(htmx, status, text)),
    };
    let op = super::field(&form, "op").unwrap_or("").to_string();
    // As `vk dev list` has it now, so a start goes to its recorded workspace and a removal
    // only to one that is still stale.
    let row = match dev_rows(local).await {
        Ok(rows) => rows.into_iter().find(|r| r.name == name),
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
    let Some((args, timeout)) = row.command(&op) else {
        return Ok(refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "Not an action this environment takes as it stands.",
        ));
    };
    if op != "start" && super::field(&form, "confirm") != Some("yes") {
        let what = match op.as_str() {
            "gc" => {
                "Remove this environment's state — its storage, keys and identity? It is \
                     not running, and this cannot be undone."
            }
            _ => {
                "Stop this environment? Its guest powers off; its state stays for the next \
                  start."
            }
        };
        return Ok(confirm(
            htmx,
            &auth,
            &format!("/dev/{name}/action"),
            &op,
            what,
        ));
    }
    run(
        ui,
        local,
        htmx,
        &auth,
        (&dev_key(name), args, timeout),
        "/dev",
    )
}

/// Start `args` as the session's action on `key`, and answer: for htmx, a line saying it
/// started, swapped into the flash; else back to `back`.
fn run(
    ui: &Ui,
    local: &Arc<Local>,
    htmx: bool,
    auth: &Auth,
    (key, args, timeout): (&str, Vec<OsString>, Duration),
    back: &str,
) -> Result<Response<Body>> {
    let principal = auth.session.principal();
    let started = local.start(&ui.hub, key, args, timeout, &principal);
    let command = match started {
        Ok(command) => command,
        Err(why) => return Ok(refused(htmx, StatusCode::CONFLICT, why)),
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
        .raw("</code>; how it ends shows on the page and in the audit log.</div>");
    Ok(swap_none(super::html_response(StatusCode::OK, h)))
}

/// The question an action that cannot be taken back asks first, in the flash's place — or,
/// for a plain form, as a page of its own — with a form that posts it again, confirmed.
fn confirm(htmx: bool, auth: &Auth, path: &str, op: &str, what: &str) -> Response<Body> {
    let mut form = Html::new();
    form.raw("<form method=\"post\" action=\"")
        .text(path)
        .raw("\" hx-post=\"")
        .text(path)
        .raw("\" hx-swap=\"none\">");
    csrf_field(&mut form, auth);
    form.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .text(op)
        .raw("\"><input type=\"hidden\" name=\"confirm\" value=\"yes\">")
        .raw("<button>yes, ")
        .text(op)
        .raw("</button></form>");
    if htmx {
        let mut h = Html::new();
        h.raw("<div id=\"flash\" hx-swap-oob=\"true\" class=\"error\">")
            .text(what)
            .raw(" ")
            .html(&form)
            .raw("</div>");
        return swap_none(super::html_response(StatusCode::OK, h));
    }
    let mut main = Html::new();
    main.raw("<h1>Confirm</h1><p>")
        .text(what)
        .raw("</p>")
        .html(&form);
    super::page(super::local::layout("confirm", auth, &main))
}

/// `resp` swapped out of band only: the page around the flash stays as it is.
fn swap_none(mut resp: Response<Body>) -> Response<Body> {
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

/// The last action on something, in a line: under way, or how it ended.
pub(super) fn action_line(h: &mut Html, action: Option<&Action>) {
    let Some(a) = action else {
        h.raw("-");
        return;
    };
    h.raw("<code>").node(&a.command).raw("</code> ");
    match &a.ended {
        None => {
            h.raw("running since ").text(pages::started(a.started_at));
        }
        Some(e) => {
            h.raw(if e.ok {
                "succeeded"
            } else {
                "<span class=\"reason\">failed</span>"
            })
            .raw(": ")
            .node(&e.said);
        }
    }
}

/// The VS Code link of a dev environment with an SSH setup, through the alias `vk dev`
/// configures: `vscode://vscode-remote/ssh-remote+<alias><folder>`. Built only of an alias and
/// a folder whose every byte is percent-encoded but the unreserved ones and `/`, so nothing in
/// either can change what the link is.
pub(super) fn vscode_link(w: &Workload) -> Option<String> {
    let alias = w.ssh_alias.as_deref()?;
    let folder = w
        .guest_workspace
        .as_deref()
        .filter(|f| f.starts_with('/'))?;
    let encode = |s: &str, keep_slash: bool| {
        let mut out = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'.' | b'_' | b'~')
                || (keep_slash && b == b'/')
            {
                out.push(char::from(b));
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    };
    Some(format!(
        "vscode://vscode-remote/ssh-remote+{}{}",
        encode(alias, false),
        encode(folder, true)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, flags: &[&str]) -> DevRow {
        DevRow {
            name: "app-1234".into(),
            workspace: Some("/src/app".into()),
            environment: Some("dev".into()),
            status: status.into(),
            booted_secs: None,
            flags: flags.iter().map(|f| f.to_string()).collect(),
        }
    }

    #[test]
    fn an_environment_is_offered_what_it_can_take() {
        let ops = |r: &DevRow| r.ops().into_iter().map(|(o, _)| o).collect::<Vec<_>>();
        assert_eq!(ops(&row("running", &[])), ["stop"]);
        assert_eq!(ops(&row("running", &["workspace-missing"])), ["stop"]);
        assert_eq!(ops(&row("stopped", &[])), ["start"]);
        assert_eq!(
            ops(&row("stopped", &["workspace-missing"])),
            ["start", "gc"]
        );
        let mut bare = row("never-booted", &["ephemeral"]);
        bare.workspace = None;
        assert_eq!(ops(&bare), ["gc"]);
        let (args, _) = row("stopped", &[]).command("start").unwrap();
        assert_eq!(
            args,
            [
                "dev",
                "up",
                "--workspace",
                "/src/app",
                "--environment",
                "dev"
            ]
            .map(OsString::from)
        );
        assert!(row("stopped", &[]).command("gc").is_none());
        assert!(row("running", &[]).command("start").is_none());
    }

    #[test]
    fn names_and_links_are_checked_and_encoded() {
        assert!(valid_dev_name("wab-12.0-4c56c17b88a2af17"));
        for bad in ["", ".", "..", ".hidden", "a/b", "a b", "a\n"] {
            assert!(!valid_dev_name(bad), "{bad:?}");
        }
        let mut w = Workload {
            id: "ab".repeat(8),
            kind: WorkloadKind::Dev,
            state_dir: "/s/app-1234".into(),
            label: None,
            project: None,
            job_name: None,
            job_id: None,
            workspace: None,
            environment: None,
            pid: Some(7),
            cpus: None,
            mem_reserved_mib: None,
            started_at: None,
            ssh_alias: Some("vk-app-1234".into()),
            guest_workspace: Some("/work dir/\"x\"".into()),
        };
        assert_eq!(
            vscode_link(&w).as_deref(),
            Some("vscode://vscode-remote/ssh-remote+vk-app-1234/work%20dir/%22x%22")
        );
        assert_eq!(key(&w), "dev/app-1234");
        assert_eq!(
            vm_command(&w, "stop").unwrap(),
            ["dev", "stop", "app-1234"].map(OsString::from)
        );
        assert!(vm_command(&w, "reboot").is_none());
        w.guest_workspace = Some("relative".into());
        assert_eq!(vscode_link(&w), None);
        w.kind = WorkloadKind::Run;
        assert_eq!(
            vm_command(&w, "reboot").unwrap(),
            ["reboot", "7"].map(OsString::from)
        );
        w.pid = None;
        assert_eq!(
            vm_command(&w, "stop").unwrap(),
            ["stop", "/s/app-1234"].map(OsString::from)
        );
        w.kind = WorkloadKind::CiJob;
        assert!(vm_ops(&w).is_empty() && vm_command(&w, "stop").is_none());
    }
}
