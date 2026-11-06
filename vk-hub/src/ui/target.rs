//! The target `vk` release on `/updates`: who set it, its rollout, held-update reasons and
//! each node's status. Operators set or clear the target, resume updates and retry failed
//! nodes through the admin socket's operations ([`crate::ops::set_target`] and the others),
//! with the same refusals as `vk-hub release target`.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::fleet::{FleetSite, ROLLOUTS_PATH, UPDATES_PATH, layout, said_so};
use super::html::Html;
use super::{Body, Ui, actions, blocking, field};
use crate::ops::TargetView;
use crate::store::{Program, Release, Role};
use crate::target::Standing;

/// Where the target's forms post.
pub(super) const PATH: &str = "/updates/target";

/// The target and the nodes' standing against it, with `steer` the forms that change it. The
/// part is live and carries no CSRF token: the page sets it as a header on htmx requests.
pub(super) fn part(h: &mut Html, view: Option<&TargetView>, releases: &[Release], steer: bool) {
    h.raw("<h3>Target release</h3>");
    let Some(view) = view else {
        h.raw("<p class=\"empty\">None: nodes are updated only when an operator updates them or starts a rollout.</p>");
        if steer {
            set_form(h, releases, None);
        }
        return;
    };
    let t = &view.target;
    h.raw("<table class=\"kv\"><tbody><tr><th>Release</th><td>vk ")
        .text(&t.version)
        .raw(" (<code title=\"")
        .text(&t.release)
        .raw("\">")
        .text(crate::store::short(&t.release))
        .raw("</code>)</td></tr><tr><th>Set</th><td>by ")
        .text(&t.set_by)
        .raw(", ")
        .html(&super::pages::at_html(t.set_at))
        .raw("</td></tr>");
    if let Some(id) = &t.rollout {
        h.raw("<tr><th>Rollout</th><td><a href=\"")
            .raw(ROLLOUTS_PATH)
            .raw("\"><code>")
            .text(crate::rollout::short_id(id))
            .raw("</code></a></td></tr>");
    }
    if let Some(why) = &t.held {
        h.raw("<tr><th>Automatic updates</th><td><span class=\"badge bad\">held</span> ")
            .node(why)
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
    if steer {
        h.raw("<div class=\"actions\">");
        if t.held.is_some() {
            button(h, "retry", None, "Resume");
        }
        button(h, "clear", None, "Clear target");
        h.raw("</div>");
    }
    standings(h, view, steer);
    if steer {
        set_form(h, releases, Some(&t.release));
    }
}

/// Statuses of nodes not on target, with Retry buttons for failed updates when `steer` is set.
fn standings(h: &mut Html, view: &TargetView, steer: bool) {
    let shown: Vec<_> = view
        .nodes
        .iter()
        .filter(|(_, _, s)| *s != Standing::Current)
        .collect();
    if shown.is_empty() {
        h.raw("<p class=\"sub\">Every node runs it.</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>node</th><th>against the target</th>");
    if steer {
        h.raw("<th></th>");
    }
    h.raw("</tr></thead><tbody>");
    for (id, hostname, standing) in shown {
        h.raw("<tr><td>");
        if vk_hub_proto::valid_id(id) {
            h.raw("<a href=\"/node/")
                .text(id)
                .raw("\">")
                .node(hostname)
                .raw("</a>");
        } else {
            h.node(hostname);
        }
        h.raw("</td><td>");
        match standing {
            Standing::Current => h.raw("current"),
            Standing::Newer { vk } => h.raw("runs a newer vk, ").node(vk).raw(": left alone"),
            Standing::Updating { command } => h
                .raw("<span class=\"badge busy\">updating</span> command <code>")
                .node(command)
                .raw("</code>"),
            Standing::Failed { reason } => h
                .raw("<span class=\"badge bad\">failed</span> ")
                .node(reason),
            Standing::Flagged { reason } => h
                .raw("<span class=\"badge bad\">its release keys refuse it</span> ")
                .node(reason),
            Standing::Held { reason } => h.raw("waiting: ").node(reason),
            Standing::Unorderable { vk } => h
                .raw("<span class=\"badge warn\">not updated automatically</span> runs vk ")
                .node(vk)
                .raw(", which is not MAJOR.MINOR.PATCH: install a release on it by hand"),
            Standing::Due => h.raw("behind: updated once it is ready"),
        };
        h.raw("</td>");
        if steer {
            h.raw("<td class=\"actions\">");
            if matches!(standing, Standing::Failed { .. }) && vk_hub_proto::valid_id(id) {
                button(h, "retry", Some(id), "Retry");
            }
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// A button posting `op`, for `node` when given.
fn button(h: &mut Html, op: &'static str, node: Option<&str>, label: &'static str) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
        .raw(op)
        .raw("\">");
    if let Some(node) = node {
        h.raw("<input type=\"hidden\" name=\"node\" value=\"")
            .text(node)
            .raw("\">");
    }
    h.raw("<button>").raw(label).raw("</button></form>");
}

/// The form making one of `releases` the target, other than `current`: a `vk` of
/// `MAJOR.MINOR.PATCH`.
fn set_form(h: &mut Html, releases: &[Release], current: Option<&str>) {
    let offered: Vec<&Release> = releases
        .iter()
        .filter(|r| {
            r.row.is(Program::Vk)
                && crate::target::orderable(&r.row.version)
                && Some(r.sha256.as_str()) != current
        })
        .collect();
    if offered.is_empty() {
        return;
    }
    let mut form = Html::new();
    form.raw("<input type=\"hidden\" name=\"op\" value=\"set\">")
        .raw("<select name=\"release\" aria-label=\"Release\" required>");
    for r in offered {
        form.raw("<option value=\"")
            .text(&r.sha256)
            .raw("\">vk ")
            .text(&r.row.version)
            .raw(" (")
            .text(crate::store::short(&r.sha256))
            .raw(")</option>");
    }
    form.raw("</select><button class=\"primary\">")
        .raw(if current.is_some() {
            "Change target"
        } else {
            "Set target"
        })
        .raw("</button>");
    // Kept while chosen from, until what it offers changes.
    let id = super::pages::preserved_id("set-target", form.as_str());
    h.raw("<form id=\"")
        .text(&id)
        .raw("\" hx-preserve=\"true\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\">")
        .html(&form)
        .raw("</form>");
}

/// `POST /updates/target`: `op=set` makes `release` the target once confirmed, `op=clear`
/// clears it, `op=retry` lets `node`, or with none every node, be tried again and resumes held
/// updates; as the operator session's principal. A status line for htmx, else back to
/// `/updates`.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let op = field(&form, "op").unwrap_or("").to_string();
    let node = field(&form, "node").map(str::to_string);
    if node.as_deref().is_some_and(|n| !vk_hub_proto::valid_id(n)) {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such node.",
        ));
    }
    let release = field(&form, "release").unwrap_or("").to_string();
    if op == "set" {
        if release.len() != 64 || !release.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                "Refused: name a release by its sha256.",
            ));
        }
        let mut detail = Html::new();
        detail
            .raw("<p>Release <code>")
            .text(crate::store::short(&release))
            .raw("</code>.</p>");
        let ask = actions::Ask {
            path: PATH.to_string(),
            back: UPDATES_PATH.to_string(),
            op: op.clone(),
            what: "Make this release the target? A rollout updates the nodes running an older \
                   version, one at a time, and nodes that fall behind later are updated on \
                   their own.",
            detail,
            asked: vec![("release", release.clone())],
        };
        if let Some(asked) = actions::ask_first(&site.questions, layout, htmx, &auth, &form, &ask)?
        {
            return Ok(asked);
        }
    }
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    let done = blocking(move || {
        Ok(match op.as_str() {
            "set" => crate::ops::set_target(&hub, &principal, &release).map(|set| {
                Some(match set.rollout {
                    Some(r) => format!(
                        "The target is vk {}; rollout {} updates the nodes behind it.",
                        set.target.version,
                        crate::rollout::short_id(&r.id)
                    ),
                    None => format!("The target is vk {}.", set.target.version),
                })
            }),
            "clear" => crate::ops::clear_target(&hub, &principal).map(|t| {
                Some(match t {
                    Some(t) => format!("Cleared the target, vk {}.", t.version),
                    None => "Nothing changed: no target was set.".to_string(),
                })
            }),
            "retry" => crate::ops::retry_target(&hub, &principal, node.as_deref()).map(
                |(retried, lifted)| {
                    Some(match (retried.len(), lifted) {
                        (0, false) => "Nothing changed: no update to retry.".to_string(),
                        (0, true) => "Automatic updates resumed.".to_string(),
                        (n, _) => format!("{n} node(s) will be tried again."),
                    })
                },
            ),
            _ => Ok(None),
        })
    })
    .await?;
    let said = match done {
        Ok(Some(said)) => said,
        Ok(None) => {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                "No such action.",
            ));
        }
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {said}."),
            ));
        }
    };
    if !htmx {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::SEE_OTHER;
        resp.headers_mut().insert(
            hyper::header::LOCATION,
            hyper::header::HeaderValue::from_static(UPDATES_PATH),
        );
        return Ok(resp);
    }
    Ok(said_so(&said))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::TargetRow;

    /// Each node not on the target says where it stands; one whose update failed offers a
    /// Retry, a flagged one says its keys refuse the release, one whose version cannot be
    /// ordered says it is not updated automatically, and a hold offers Resume.
    #[test]
    fn the_nodes_standing_is_shown_with_what_an_operator_can_do() {
        let target = TargetRow {
            release: "ab".repeat(32),
            version: "1.2.3".into(),
            signature: None,
            set_at: 1,
            set_by: "uid 0".into(),
            rollout: Some("ef".repeat(16)),
            held: Some("rollout efefefef was aborted".into()),
            nodes: Default::default(),
        };
        let (a, b) = ("12".repeat(16), "34".repeat(16));
        let view = TargetView {
            target,
            nodes: vec![
                (
                    a.clone(),
                    "ci-a".into(),
                    Standing::Failed {
                        reason: "refused <x>".into(),
                    },
                ),
                (
                    b,
                    "ci-b".into(),
                    Standing::Flagged {
                        reason: "unsigned".into(),
                    },
                ),
                ("56".repeat(16), "ci-c".into(), Standing::Current),
                (
                    "78".repeat(16),
                    "ci-d".into(),
                    Standing::Unorderable {
                        vk: "1.3.0-rc1".into(),
                    },
                ),
            ],
        };
        let mut h = Html::new();
        part(&mut h, Some(&view), &[], true);
        let text = h.into_string();
        for want in [
            "<span class=\"badge bad\">held</span> rollout efefefef was aborted",
            "<button>Resume</button>",
            "<button>Clear target</button>",
            "<span class=\"badge bad\">failed</span> refused &lt;x&gt;",
            &format!("name=\"node\" value=\"{a}\"><button>Retry</button>"),
            "its release keys refuse it</span> unsigned",
            "not updated automatically</span> runs vk 1.3.0-rc1,",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        assert!(!text.contains("ci-c"), "{text}");
        assert_eq!(text.matches("<button>Retry</button>").count(), 1);
        let mut h = Html::new();
        part(&mut h, Some(&view), &[], false);
        assert!(!h.into_string().contains("<button"));
    }
}
