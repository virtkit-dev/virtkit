//! Shared update UI for registries, GitLab relays and the hub itself. Each [`Kind`] has a
//! live `/updates` section listing versions and updates, a release form, and an action
//! handler requiring confirmation ([`actions::ask_first`]). Each kind's module supplies
//! lookup, checks and command issuance ([`Ops`]).

use std::sync::Arc;

use anyhow::Result;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use vk_hub_proto::{Outcome, UpdateProgress};

use super::fleet::FleetSite;
use super::html::Html;
use super::pages::{self, header_cells};
use super::{Auth, Body, Ui, actions, blocking, field};
use crate::server::Hub;
use crate::store::{NotEnrolled, Program, Release};

/// What updates itself on the hub's command: a kind of peer, or the hub itself.
pub(super) struct Kind {
    /// What one is called, in a sentence: `registry`.
    pub(super) noun: &'static str,
    /// Its section's heading.
    pub(super) heading: &'static str,
    /// Its table's first column.
    pub(super) column: &'static str,
    /// The program of the releases it runs.
    pub(super) program: Program,
    /// What an update does to one, under its section.
    pub(super) note: &'static str,
    /// The question an update asks.
    pub(super) question: &'static str,
    /// How long an update waits for an offline one to connect and take it.
    pub(super) command_ttl: std::time::Duration,
    /// The setting that keeps the hub from updating one, as it follows "not allowed by its ":
    /// `<code>[hub] allow</code>, which lacks <code>update</code>`.
    pub(super) allow: &'static str,
    /// The setting that lets one go back a version: `<code>[hub] allow_downgrade</code>`.
    pub(super) allow_downgrade: &'static str,
    /// What an operator is told once an update started: given the one updated, the program,
    /// version and ID.
    pub(super) started: fn(&str, Program, &str, &str) -> String,
    /// How one's update is looked up, checked and issued.
    pub(super) ops: Ops,
}

/// Reported state and last update for a peer or the hub, as shown in its section.
pub(super) struct Peer {
    pub(super) id: String,
    pub(super) hostname: String,
    /// Its page, when it has one.
    pub(super) page: Option<String>,
    /// Where its update form posts.
    pub(super) action: String,
    /// The version it last reported running.
    pub(super) version: Option<String>,
    pub(super) connected: bool,
    /// Whether its [`Kind::allow`] lets the hub update it: `None` until it reports its
    /// inventory, or for a hub that does not update itself.
    pub(super) takes_updates: Option<bool>,
    /// Whether its [`Kind::allow_downgrade`] is set: `None` when the hub does not know.
    pub(super) allows_downgrade: Option<bool>,
    /// Whether it takes only signed releases.
    pub(super) requires_signed: bool,
    /// Its update as it last reported it.
    pub(super) reported: Option<UpdateProgress>,
    /// The last update the hub issued it.
    pub(super) last: Option<Issued>,
}

/// An update command the hub issued, with its reported outcome.
pub(super) struct Issued {
    pub(super) id: String,
    pub(super) version: String,
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    pub(super) outcome: Option<Outcome>,
}

/// Lookup, checks and update issuance for a [`Kind`].
pub(super) struct Ops {
    /// Find `id`; `None` if absent.
    pub(super) find: fn(&Hub, &str) -> Result<Option<Peer>>,
    /// Why the hub refuses to update `id` to the release given, going by what it last
    /// reported.
    pub(super) check: fn(&Hub, &str, &Release) -> Result<()>,
    /// Update `id` to the release as shown, as the actor given, while it runs the version
    /// given; the update's ID.
    pub(super) issue: Issue,
}

/// [`Ops::issue`] takes `&Arc<Hub>` so the hub's update can spawn its hand-over with a clone.
pub(super) type Issue = fn(&Arc<Hub>, &str, &str, &Release, Option<&str>) -> Result<String>;

/// The live `/updates` section for `kind`'s `peers`: versions, update permissions and
/// update status. With `steer`, include update forms for peers that allow updates.
/// Render nothing when `peers` is empty.
pub(super) fn section(
    h: &mut Html,
    kind: &Kind,
    peers: &[Peer],
    releases: &[Release],
    steer: bool,
    now: u64,
) {
    if peers.is_empty() {
        return;
    }
    h.raw("<section><h2>")
        .raw(kind.heading)
        .raw("</h2><table class=\"grid\"><thead><tr>");
    let mut headers = vec![
        kind.column,
        "VERSION",
        "CONNECTION",
        "UPDATES",
        "LAST UPDATE",
    ];
    if steer {
        headers.push("UPDATE TO");
    }
    header_cells(h, &headers);
    h.raw("</tr></thead><tbody>");
    for p in peers {
        h.raw("<tr><td>");
        match &p.page {
            Some(page) => h
                .raw("<a href=\"")
                .text(page)
                .raw("\">")
                .node(&p.hostname)
                .raw("</a>"),
            // A peer by its ID too, as hostnames need not be unique; the hub by its name.
            None if vk_hub_proto::valid_id(&p.id) => h
                .node(&p.hostname)
                .raw(" <code class=\"sub\">")
                .text(crate::rollout::short_id(&p.id))
                .raw("</code>"),
            None => h.node(&p.hostname),
        };
        h.raw("</td><td>");
        match &p.version {
            Some(v) => h.node(v),
            None => h.raw("-"),
        };
        h.raw("</td><td>").raw(if p.connected {
            "<span class=\"badge ok\">Online</span>"
        } else {
            "<span class=\"badge bad\">Offline</span>"
        });
        h.raw("</td><td>");
        policy(h, kind, p);
        h.raw("</td><td>");
        status(h, p, now);
        h.raw("</td>");
        if steer {
            h.raw("<td>");
            form(h, kind, p, releases, None);
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table><p class=\"sub\">")
        .raw(kind.note)
        .raw("</p></section>");
}

/// Whether `p` lets the hub update it, and to what.
fn policy(h: &mut Html, kind: &Kind, p: &Peer) {
    match p.takes_updates {
        None => h.raw("not reported yet"),
        Some(false) => h.raw("not allowed by its ").raw(kind.allow),
        Some(true) if p.requires_signed => h.raw("signed releases only"),
        Some(true) => h.raw("unsigned accepted"),
    };
}

/// Show `p`'s reported update progress or result, falling back to the last issued command
/// while it is pending or after refusal or failure.
fn status(h: &mut Html, p: &Peer, now: u64) {
    // What the peer reports of the last command, once it took it; of an earlier one only when
    // the hub keeps no command.
    let reported = p.reported.as_ref().filter(|u| {
        p.last.as_ref().is_none_or(|c| {
            u.command == c.id && matches!(c.outcome, Some(Outcome::Accepted | Outcome::Done))
        })
    });
    match (reported, &p.last) {
        (Some(u), _) => {
            h.node(&u.version)
                .raw(" ")
                .text(crate::store::update_phase_name(u.phase));
            if let Some(m) = &u.message {
                h.raw(": ").node(m);
            }
        }
        (None, Some(c)) => command_line(h, c, now),
        (None, None) => {
            h.raw("-");
        }
    }
}

/// Update command `c`: the version it names, and whether the peer took it.
fn command_line(h: &mut Html, c: &Issued, now: u64) {
    h.raw("to ").node(&c.version).raw(": ");
    match &c.outcome {
        None if c.expires_at <= now => h.raw("expired, never taken"),
        None => h.raw("not taken yet"),
        Some(Outcome::Accepted) => h.raw("under way"),
        Some(Outcome::Done) => h.raw("done"),
        Some(Outcome::Failed { message }) => h
            .raw("<span class=\"reason\">failed</span>: ")
            .node(message),
        Some(Outcome::Refused { reason }) => h
            .raw("<span class=\"reason\">refused</span>: ")
            .node(reason),
        Some(Outcome::Expired) => h.raw("expired"),
    };
    h.raw(", issued ").html(&pages::at_html(c.issued_at));
}

/// [`Kind::started`] for a peer, which the update is sent to.
pub(super) fn sent(peer: &str, program: Program, version: &str, command: &str) -> String {
    format!(
        "Sent {peer} the update to {program} {version} (command {command}). Its progress shows \
         on this page."
    )
}

/// Render the release form for `p` and `kind`'s program, or explain why no form is available.
/// On a peer's page, use a plain form carrying `csrf`. In `/updates`' shared fragment,
/// omit `csrf` and post through htmx with the page's token; `hx-preserve` keeps the input
/// until the release choices change.
pub(super) fn form(h: &mut Html, kind: &Kind, p: &Peer, releases: &[Release], csrf: Option<&str>) {
    if p.takes_updates == Some(false) {
        h.raw("<span class=\"sub\">Not allowed by its ")
            .raw(kind.allow)
            .raw(".</span>");
        return;
    }
    // Those it would take: signed ones only, if it says it requires them.
    let releases: Vec<&Release> = releases
        .iter()
        .filter(|r| r.row.is(kind.program) && (!p.requires_signed || r.row.signature.is_some()))
        .collect();
    if releases.is_empty() {
        h.raw("<span class=\"sub\">Add a ")
            .raw(if p.requires_signed { "signed " } else { "" })
            .raw(kind.program.name())
            .raw(" release first.</span>");
        return;
    }
    let mut form = Html::new();
    form.raw("<input type=\"hidden\" name=\"op\" value=\"update\">")
        .raw("<select name=\"release\" aria-label=\"Release\" required>");
    for r in releases {
        form.raw("<option value=\"")
            .text(&r.sha256)
            .raw("\">")
            .text(&r.row.version)
            .raw(" (")
            .text(crate::store::short(&r.sha256))
            .raw(if r.row.signature.is_some() {
                ", signed)"
            } else {
                ")"
            })
            .raw("</option>");
    }
    form.raw("</select><button>Update</button>");
    h.raw("<form class=\"act\" method=\"post\" action=\"")
        .text(&p.action)
        .raw("\"");
    match csrf {
        Some(csrf) => {
            h.raw(">");
            pages::csrf_input(h, csrf);
        }
        None => {
            let id = pages::preserved_id(
                &format!("{}-update", kind.noun),
                &format!("{}{}", p.id, form.as_str()),
            );
            h.raw(" id=\"")
                .text(&id)
                .raw("\" hx-preserve=\"true\" hx-post=\"")
                .text(&p.action)
                .raw("\" hx-swap=\"none\">");
        }
    }
    h.html(&form).raw("</form>");
}

/// Why a peer running one version refuses to update to another, as its own check decides
/// ([`vk_peer::trial::check_version`], which registries, relays and the hub run).
#[derive(Debug, PartialEq, Eq)]
enum VersionRefusal {
    /// An older `MAJOR.MINOR.PATCH`, unless its [`Kind::allow_downgrade`].
    Older,
    /// A version not ordered against its own as `MAJOR.MINOR.PATCH`, always.
    Unordered,
}

/// Why a peer running `own` would refuse to update to `candidate`; `None` when it takes it.
fn version_refusal(candidate: &str, own: &str) -> Option<VersionRefusal> {
    let fields = |v: &str| -> Option<Vec<u64>> {
        let v: Vec<u64> = v
            .split('.')
            .map(|f| f.parse().ok())
            .collect::<Option<_>>()?;
        (v.len() == 3).then_some(v)
    };
    match (fields(candidate), fields(own)) {
        (Some(c), Some(o)) if c < o => Some(VersionRefusal::Older),
        (Some(_), Some(_)) => None,
        _ if candidate == own => None,
        _ => Some(VersionRefusal::Unordered),
    }
}

/// What updating `p` to `release` would do, for its question.
fn detail(kind: &Kind, p: &Peer, release: &Release) -> Html {
    let mut h = Html::new();
    h.raw("<p>")
        .raw(kind.program.name())
        .raw(" ")
        .text(&release.row.version)
        .raw(" (<code>")
        .text(crate::store::short(&release.sha256))
        .raw("</code>")
        .raw(if release.row.signature.is_some() {
            ", signed"
        } else {
            ", unsigned"
        })
        .raw(") to ")
        .node(&p.hostname);
    if let Some(own) = &p.version {
        h.raw(", which runs ").node(own);
    }
    h.raw(".</p>");
    match p
        .version
        .as_deref()
        .and_then(|own| version_refusal(&release.row.version, own))
    {
        Some(VersionRefusal::Older) if p.allows_downgrade == Some(true) => {
            h.raw("<p>This release is older than the version the ")
                .raw(kind.noun)
                .raw(" runs. The ")
                .raw(kind.noun)
                .raw("'s ")
                .raw(kind.allow_downgrade)
                .raw(" lets it go back.</p>");
        }
        Some(VersionRefusal::Older) => {
            h.raw("<p class=\"reason\">This release is older than the version the ")
                .raw(kind.noun)
                .raw(" runs. The ")
                .raw(kind.noun)
                .raw(" refuses it unless its ")
                .raw(kind.allow_downgrade)
                .raw(" is set.</p>");
        }
        Some(VersionRefusal::Unordered) => {
            h.raw("<p class=\"reason\">The ")
                .raw(kind.noun)
                .raw(" refuses this release. Its version cannot be ordered against the version ")
                .raw("the ")
                .raw(kind.noun)
                .raw(" runs: both must be <code>MAJOR.MINOR.PATCH</code>.</p>");
        }
        None => {}
    }
    if !p.connected {
        h.raw("<p>The ")
            .raw(kind.noun)
            .raw(" is offline. It gets the update if it connects within ")
            .text(crate::human_duration(kind.command_ttl))
            .raw(".</p>");
    }
    h
}

/// `op=update` posted to peer `id`'s action path: update it to the release `form` names, once
/// the operator has confirmed it, by `kind`'s [`Ops`]. Back to `/updates` from there, or to
/// the peer's page from its plain form.
pub(super) async fn update(
    ui: &Ui,
    site: &FleetSite,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    kind: &'static Kind,
    id: &str,
) -> Result<Response<Body>> {
    let ops = &kind.ops;
    let no_such = format!("There is no such {}.", kind.noun);
    let sha256 = field(form, "release").unwrap_or("").to_string();
    if !vk_hub_proto::valid_sha256(&sha256) {
        return Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "Refused: choose a release.",
        ));
    }
    let (hub, wanted, sha) = (ui.hub.clone(), id.to_string(), sha256.clone());
    let found = blocking(move || {
        let Some(peer) = (ops.find)(&hub, &wanted)? else {
            return Ok(None);
        };
        let Some(row) = hub.db.release(&sha)? else {
            return Ok(Some((peer, None)));
        };
        let release = Release { sha256: sha, row };
        let refusal = (ops.check)(&hub, &wanted, &release);
        Ok::<_, anyhow::Error>(Some((peer, Some((release, refusal)))))
    })
    .await?;
    let Some((peer, release)) = found else {
        return Ok(actions::refused(htmx, StatusCode::NOT_FOUND, &no_such));
    };
    let Some((release, refusal)) = release else {
        return Ok(actions::refused(
            htmx,
            StatusCode::CONFLICT,
            "Refused: the hub no longer holds that release.",
        ));
    };
    if let Err(e) = refusal {
        if e.is::<NotEnrolled>() {
            return Ok(actions::refused(htmx, StatusCode::NOT_FOUND, &no_such));
        }
        let said = vk_hub_proto::display_safe(&format!("{e:#}"));
        return Ok(actions::refused(
            htmx,
            StatusCode::CONFLICT,
            &format!("Refused: {said}."),
        ));
    }
    let back = match &peer.page {
        Some(page) if !htmx => page.clone(),
        _ => super::fleet::UPDATES_PATH.to_string(),
    };
    let ask = actions::Ask {
        path: peer.action.clone(),
        back: back.clone(),
        op: "update".to_string(),
        what: kind.question,
        detail: detail(kind, &peer, &release),
        asked: vec![
            ("release", release.sha256.clone()),
            ("version", release.row.version.clone()),
            (
                "signature",
                release.row.signature.clone().unwrap_or_default(),
            ),
            ("running", peer.version.clone().unwrap_or_default()),
        ],
    };
    if let Some(asked) = actions::ask_first(
        &site.questions,
        super::fleet::layout,
        htmx,
        auth,
        form,
        &ask,
    )? {
        return Ok(asked);
    }
    let (hub, principal, target) = (ui.hub.clone(), auth.session.principal(), id.to_string());
    let (shown, running) = (release.clone(), peer.version.clone());
    let issued = blocking(move || {
        Ok((ops.issue)(
            &hub,
            &principal,
            &target,
            &shown,
            running.as_deref(),
        ))
    })
    .await?;
    match issued {
        Ok(command) if htmx => Ok(super::fleet::said_so(&(kind.started)(
            &vk_hub_proto::display_safe(&peer.hostname),
            kind.program,
            &release.row.version,
            &command,
        ))),
        Ok(_) => Ok(see_other(&back)),
        Err(e) if e.is::<NotEnrolled>() => {
            Ok(actions::refused(htmx, StatusCode::NOT_FOUND, &no_such))
        }
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

/// A redirect to the hub's own `location`.
fn see_other(location: &str) -> Response<Body> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .unwrap_or(HeaderValue::from_static(super::fleet::UPDATES_PATH)),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An update is refused as the peer's own check refuses it: to an older version, or to one
    /// that cannot be ordered against its own.
    #[test]
    fn a_version_the_peer_refuses_is_said() {
        assert_eq!(version_refusal("0.90.1", "0.90.0"), None);
        assert_eq!(version_refusal("0.90.0", "0.90.0"), None);
        assert_eq!(
            version_refusal("0.89.9", "0.90.0"),
            Some(VersionRefusal::Older)
        );
        assert_eq!(
            version_refusal("0.90", "0.90.0"),
            Some(VersionRefusal::Unordered)
        );
        assert_eq!(
            version_refusal("0.90.0", "dev"),
            Some(VersionRefusal::Unordered)
        );
        assert_eq!(version_refusal("dev", "dev"), None);
    }
}
