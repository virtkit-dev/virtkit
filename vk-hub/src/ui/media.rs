//! Install media ([`crate::media`]): what each is, where it came from, its licence, and where
//! it is.
//!
//! **The list**, `/media`, for any viewer: every medium the hub uploaded, with what it
//! installs, its licence and when it must be renewed, whether jobs may use it and which
//! registries hold it; for an operator, the upload form.
//!
//! **A medium's page**, `/media/<sha256>`: everything said of it and where each registry holds
//! it; for an operator, its approval, the form that edits what is said of it, its rename, which
//! retags the registries holding it ([`crate::media::rename`]), and its removal, confirmed
//! first.
//!
//! **An upload** is `vk-hub media add` from a browser: a plain form post,
//! `multipart/form-data`, its CSRF token and what is said of the medium first — checked, within
//! a deadline of their own, before the file is read — then the file, last, its length known from
//! the body's. Its start is read for the volume label, then it goes on to the registry as it
//! arrives ([`crate::media::send`]), under the release upload's rate floor and pauses, its last
//! chunk only once the body ended whole; the medium is recorded once the registry confirms it,
//! as the session's principal, whose role is checked again then.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::fleet::FleetSite;
use super::html::Html;
use super::multipart::{self, Multipart, Refusal};
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, message};
use crate::store::{LicenseKind, Medium, MediumEdit, MediumInfo, MediumKind, Role, days_of};

/// The list's path, and the prefix of a medium's page.
pub(super) const PATH: &str = "/media";

/// Where a medium is uploaded to.
pub(super) const UPLOAD_PATH: &str = "/media/upload";

/// The longest a field of a form may be but for sources and, sent with CRLF line breaks, texts.
const MAX_TEXT: usize = crate::store::MAX_TEXT;

/// What a form's fields and the multipart framing may add to the file.
const FORM_OVERHEAD: u64 = 128 * 1024;

/// The largest form posted to edit a medium: every field at its longest, each byte
/// percent-encoded.
const MAX_EDIT: usize = 256 * 1024;

/// How near its date a medium's renewal is flagged.
const RENEW_SOON_DAYS: i64 = 30;

/// The path of medium `sha256`'s page.
pub(super) fn detail_path(sha256: &str) -> String {
    format!("{PATH}/{sha256}")
}

/// The sha256 a medium's page's `path` names, if it is one.
pub(super) fn detail_target(path: &str) -> Option<&str> {
    let sha = path.strip_prefix(PATH)?.strip_prefix('/')?;
    vk_hub_proto::valid_sha256(sha).then_some(sha)
}

/// What an action's `path`, `/media/<sha256>/<op>`, names: the medium and the operation.
pub(super) fn action_target(path: &str) -> Option<(&str, &str)> {
    let (sha, op) = path
        .strip_prefix(PATH)?
        .strip_prefix('/')?
        .split_once('/')?;
    (vk_hub_proto::valid_sha256(sha)
        && matches!(op, "edit" | "rename" | "approve" | "unapprove" | "remove"))
    .then_some((sha, op))
}

fn see_other(path: &str) -> Result<Response<Body>> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_str(path)?);
    Ok(resp)
}

/// `GET /media`.
pub(super) async fn list(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let operator = auth.session.role >= Role::Operator;
    let (media, choices) = blocking(move || {
        let choices = if operator {
            Some(crate::media::choices(&hub)?)
        } else {
            None
        };
        Ok((hub.db.media()?, choices))
    })
    .await?;
    let today = today();
    let mut h = Html::new();
    h.raw("<h1>Install media</h1><p class=\"sub\">Windows installation and driver media ")
        .raw("for Windows builds. Jobs placed by the hub use those approved fleet-wide, on ")
        .raw("nodes that do not set their own list.</p><section>");
    if media.is_empty() {
        h.raw("<p class=\"empty\">none yet.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>name</th><th>kind</th><th>installs</th>")
            .raw("<th>licence</th><th>renew by</th><th>jobs</th><th>registries</th>")
            .raw("<th>size</th><th>uploaded</th></tr></thead><tbody>");
        for m in &media {
            let i = &m.row.info;
            h.raw("<tr><td><a href=\"")
                .text(detail_path(&m.sha256))
                .raw("\">")
                .text(&m.row.file_name)
                .raw("</a> <code class=\"sub\" title=\"")
                .text(&m.sha256)
                .raw("\">")
                .text(crate::store::short(&m.sha256))
                .raw("</code></td><td>")
                .text(i.kind.label())
                .raw("</td><td>")
                .text(installs(i))
                .raw("</td><td>")
                .text(i.license.label())
                .raw("</td><td>");
            renew_by(&mut h, i, today);
            h.raw("</td><td>");
            approval(&mut h, m.approved);
            let mut registries: Vec<&str> = Vec::new();
            for l in &m.row.locations {
                if !registries.contains(&l.registry.as_str()) {
                    registries.push(&l.registry);
                }
            }
            let registries: Vec<&str> = registries.into_iter().map(crate::store::short).collect();
            h.raw("</td><td>")
                .text(registries.join(", "))
                .raw("</td><td>")
                .text(pages::bytes(m.row.size))
                .raw("</td><td>")
                .html(&pages::at_html(m.row.added_at))
                .raw(" by ")
                .text(&m.row.added_by)
                .raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section>");
    if let Some((able, named)) = &choices {
        upload_form(&mut h, auth, able, named.as_deref());
    }
    Ok(super::page(super::fleet::layout("Media", PATH, auth, &h)))
}

/// Today, in days since the Unix epoch.
fn today() -> i64 {
    i64::try_from(crate::now_secs() / 86_400).unwrap_or(i64::MAX)
}

/// What `i` installs, in a few words: product, edition, version, build, language, arch.
fn installs(i: &MediumInfo) -> String {
    [
        &i.product,
        &i.edition,
        &i.version,
        &i.build,
        &i.language,
        &i.arch,
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .map(String::as_str)
    .collect::<Vec<_>>()
    .join(" ")
}

/// `i`'s renewal date, flagged once it is near or past.
fn renew_by(h: &mut Html, i: &MediumInfo, today: i64) {
    let Some(days) = days_of(&i.expires) else {
        return;
    };
    h.text(&i.expires);
    let left = days - today;
    if left < 0 {
        h.raw(" <span class=\"badge bad\">")
            .text(format!("{} days ago", -left))
            .raw("</span>");
    } else if left <= RENEW_SOON_DAYS {
        h.raw(" <span class=\"badge warn\">")
            .text(format!("in {left} days"))
            .raw("</span>");
    }
}

fn approval(h: &mut Html, approved: bool) {
    if approved {
        h.raw("<span class=\"badge ok\">approved</span>");
    } else {
        h.raw("<span class=\"sub\">not approved</span>");
    }
}

/// The fields that say what a medium is, filled from `i`; with `detect`, its kind left to its
/// volume label unless chosen.
fn info_fields(h: &mut Html, i: &MediumInfo, detect: bool) {
    h.raw("<label>Kind <select name=\"kind\">");
    if detect {
        h.raw("<option value=\"\" selected>From its volume label</option>");
    }
    for k in MediumKind::ALL {
        h.raw("<option value=\"")
            .raw(k.name())
            .raw(if k == i.kind && !detect {
                "\" selected>"
            } else {
                "\">"
            })
            .text(k.label())
            .raw("</option>");
    }
    h.raw("</select></label>");
    for (name, label, value, hint) in [
        ("product", "Product", &i.product, "Windows Server 2025"),
        ("edition", "Edition", &i.edition, "Datacenter Evaluation"),
        ("version", "Version", &i.version, "24H2"),
        ("build", "Build", &i.build, "26100.1742"),
        ("language", "Language", &i.language, "en-us"),
        ("arch", "Architecture", &i.arch, "x64"),
    ] {
        h.raw("<label>")
            .text(label)
            .raw(" <input name=\"")
            .raw(name)
            .raw("\" size=\"24\" maxlength=\"256\" value=\"")
            .text(value)
            .raw("\" placeholder=\"")
            .text(hint)
            .raw("\"></label>");
    }
    // Each textarea's text starts on a line of its own: HTML drops a line break right after
    // the tag, which would drop a leading one of the text.
    h.raw("<label>Sources, one URL a line <textarea name=\"sources\" rows=\"2\" cols=\"60\">\n")
        .text(i.sources.join("\n"))
        .raw("</textarea></label><label>Downloaded on <input type=\"date\" name=\"obtained\" ")
        .raw("value=\"")
        .text(&i.obtained)
        .raw("\"></label><label>Licence <select name=\"license\">");
    for k in LicenseKind::ALL {
        h.raw("<option value=\"")
            .raw(k.name())
            .raw(if k == i.license {
                "\" selected>"
            } else {
                "\">"
            })
            .text(k.label())
            .raw("</option>");
    }
    h.raw("</select></label>");
    for (name, label, value, hint) in [
        (
            "license_terms",
            "Licence terms",
            &i.license_terms,
            "Activated at build; each build runs 180 days.",
        ),
        (
            "renewal",
            "Renewal",
            &i.renewal,
            "Download the current evaluation ISO and upload it.",
        ),
    ] {
        h.raw("<label>")
            .text(label)
            .raw(" <textarea name=\"")
            .raw(name)
            .raw("\" rows=\"2\" cols=\"60\" placeholder=\"")
            .text(hint)
            .raw("\">\n")
            .text(value)
            .raw("</textarea></label>");
    }
    h.raw("<label>Renew by <input type=\"date\" name=\"expires\" value=\"")
        .text(&i.expires)
        .raw("\"></label><label>Notes <textarea name=\"notes\" rows=\"3\" cols=\"60\">\n")
        .text(&i.notes)
        .raw("</textarea></label>");
}

/// The upload form, folded behind a button: `able`, the registries that can take it, and the
/// one the fleet-wide setting `named`.
fn upload_form(h: &mut Html, auth: &Auth, able: &[(String, String)], named: Option<&str>) {
    h.raw("<details class=\"upload\"><summary class=\"button\">Upload a medium</summary>");
    if able.is_empty() {
        h.raw("<p class=\"sub\">No registry can take one now. Connect one, update it if it is ")
            .raw("older than this hub, and bind its URL on the <a href=\"")
            .raw(super::registries::PATH)
            .raw("\">Storage</a> tab.</p></details>");
        return;
    }
    h.raw("<form class=\"wide\" method=\"post\" action=\"")
        .raw(UPLOAD_PATH)
        .raw("\" enctype=\"multipart/form-data\">");
    // Before the file: the hub checks them before it reads it.
    csrf_field(h, auth);
    registry_choice(h, able, named);
    h.raw("<label>Repository path <input name=\"under\" size=\"24\" ")
        .raw("placeholder=\"build-cache\"></label><p class=\"sub\">What the nodes' ")
        .raw("<code>[build] cache_registry</code> names past the registry's host, if ")
        .raw("anything.</p><label><input type=\"checkbox\" name=\"approve\" value=\"yes\" ")
        .raw("checked> Approve for jobs fleet-wide</label>");
    info_fields(h, &MediumInfo::default(), true);
    h.raw("<label>File <input type=\"file\" name=\"file\" required></label>")
        .raw("<button class=\"primary\">Upload</button></form><p class=\"sub\">Left blank, a ")
        .raw("Windows ISO's kind, architecture and language, and a virtio-win ISO's product and ")
        .raw("version, are read from its volume label. Keep this page open until the upload ")
        .raw("ends; it must arrive at ")
        .text(pages::bytes(super::operations::MIN_RATE))
        .raw("/s or faster.</p></details>");
}

/// The registry select of the upload form: `able`, with the one `named` selected, or the only
/// one; otherwise one must be chosen.
fn registry_choice(h: &mut Html, able: &[(String, String)], named: Option<&str>) {
    let chosen = match named {
        Some(id) => able.iter().any(|(a, _)| a == id).then_some(id),
        None => match able {
            [(only, _)] => Some(only.as_str()),
            _ => None,
        },
    };
    h.raw("<label>Registry <select name=\"registry\" required>");
    if chosen.is_none() {
        h.raw("<option value=\"\" selected disabled>Choose one</option>");
    }
    for (id, host) in able {
        h.raw("<option value=\"")
            .text(id)
            .raw(if Some(id.as_str()) == chosen {
                "\" selected>"
            } else {
                "\">"
            })
            .text(host)
            .raw(" (")
            .text(crate::store::short(id))
            .raw(")</option>");
    }
    h.raw("</select></label>");
}

/// `GET /media/<sha256>`.
pub(super) async fn detail(auth: &Auth, ui: &Ui, sha256: &str) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let sha = sha256.to_string();
    let Some(m) = blocking(move || hub.db.medium(&sha)).await? else {
        return Ok(message(StatusCode::NOT_FOUND, "There is no such medium."));
    };
    let revision = m.revision()?;
    let operator = (auth.session.role >= Role::Operator).then_some((auth, revision.as_str()));
    let mut h = Html::new();
    medium_page(&mut h, &m, operator, today());
    Ok(super::page(super::fleet::layout(
        &m.row.file_name,
        PATH,
        auth,
        &h,
    )))
}

/// Medium `m`'s page; with an operator's `auth` and the medium's revision, its approval, edit
/// and removal.
fn medium_page(h: &mut Html, m: &Medium, operator: Option<(&Auth, &str)>, today: i64) {
    let (i, row) = (&m.row.info, &m.row);
    h.raw("<h1>")
        .text(&row.file_name)
        .raw("</h1><p class=\"sub\">")
        .text(i.kind.label())
        .raw(" · <code>")
        .text(&m.sha256)
        .raw("</code> · <a href=\"")
        .raw(PATH)
        .raw("\">All media</a></p>");

    pages::section(h, "What it is");
    for (k, v) in [
        ("Product", &i.product),
        ("Edition", &i.edition),
        ("Version", &i.version),
        ("Build", &i.build),
        ("Language", &i.language),
        ("Architecture", &i.arch),
    ] {
        if !v.is_empty() {
            pages::kv(h, k, v);
        }
    }
    if let Some(label) = &row.volume_label {
        pages::kv(h, "Volume label", label);
    }
    pages::kv(h, "Size", &pages::bytes(row.size));
    pages::end_section(h);

    pages::section(h, "Where it comes from");
    if !i.sources.is_empty() {
        let mut links = Html::new();
        for (n, url) in i.sources.iter().enumerate() {
            if n > 0 {
                links.raw("<br>");
            }
            links.external_link(Some(url), url);
        }
        pages::kv_html(h, "Sources", &links);
    }
    if !i.obtained.is_empty() {
        pages::kv(h, "Downloaded on", &i.obtained);
    }
    let mut added = pages::at_html(row.added_at);
    added.raw(" by ").text(&row.added_by);
    pages::kv_html(h, "Uploaded", &added);
    if let (Some(at), Some(by)) = (row.edited_at, &row.edited_by) {
        let mut edited = pages::at_html(at);
        edited.raw(" by ").text(by);
        pages::kv_html(h, "Last edited", &edited);
    }
    pages::end_section(h);

    pages::section(h, "Licence");
    pages::kv(h, "Kind", i.license.label());
    for (k, v) in [("Terms", &i.license_terms), ("Renewal", &i.renewal)] {
        if !v.is_empty() {
            let mut text = Html::new();
            text.raw("<span class=\"pre\">").text(v).raw("</span>");
            pages::kv_html(h, k, &text);
        }
    }
    if !i.expires.is_empty() {
        let mut by = Html::new();
        renew_by(&mut by, i, today);
        pages::kv_html(h, "Renew by", &by);
    }
    if !i.notes.is_empty() {
        let mut notes = Html::new();
        notes
            .raw("<span class=\"pre\">")
            .text(&i.notes)
            .raw("</span>");
        pages::kv_html(h, "Notes", &notes);
    }
    pages::end_section(h);

    h.raw("<section><h2>Where it is</h2><p>");
    approval(h, m.approved);
    h.raw(if m.approved {
        " Jobs placed by the hub may use it, on nodes that do not set their own list."
    } else {
        " Jobs placed by the hub use it only on nodes whose own settings list it."
    })
    .raw("</p>");
    if let Some((auth, _)) = operator {
        let (op, label) = if m.approved {
            ("unapprove", "Withdraw approval")
        } else {
            ("approve", "Approve for jobs")
        };
        action_button(h, auth, &m.sha256, op, label);
    }
    h.raw("<table class=\"grid\"><thead><tr><th>registry</th><th>stored as</th>")
        .raw("<th>manifest</th><th>uploaded</th></tr></thead><tbody>");
    for l in &row.locations {
        let under = l.under.as_ref().map_or(String::new(), |u| format!("{u}/"));
        h.raw("<tr><td><a href=\"/registry/")
            .text(&l.registry)
            .raw("\">")
            .text(crate::store::short(&l.registry))
            .raw("</a></td><td><code>")
            .text(format!("{under}files/sha256:{}", m.sha256))
            .raw("</code><br><code>")
            .text(format!("{under}files/{}:{}", crate::media::DIR, l.name))
            .raw("</code></td><td><code title=\"")
            .text(&l.manifest)
            .raw("\">")
            .text(crate::store::short(
                l.manifest.trim_start_matches("sha256:"),
            ))
            .raw("</code></td><td>")
            .html(&pages::at_html(l.at))
            .raw(" by ")
            .text(&l.by)
            .raw("</td></tr>");
    }
    h.raw("</tbody></table></section>");

    if let Some((auth, revision)) = operator {
        h.raw("<details class=\"upload\"><summary class=\"button\">Edit</summary>")
            .raw("<form class=\"wide\" method=\"post\" action=\"")
            .text(format!("{}/edit", detail_path(&m.sha256)))
            .raw("\">");
        csrf_field(h, auth);
        h.raw("<input type=\"hidden\" name=\"was\" value=\"")
            .text(revision)
            .raw("\">");
        info_fields(h, i, false);
        h.raw("<button class=\"primary\">Save</button></form></details>")
            .raw("<details class=\"upload\"><summary class=\"button\">Rename</summary>")
            .raw("<form class=\"wide\" method=\"post\" action=\"")
            .text(format!("{}/rename", detail_path(&m.sha256)))
            .raw("\">");
        csrf_field(h, auth);
        h.raw("<input type=\"hidden\" name=\"was\" value=\"")
            .text(revision)
            .raw("\"><label>Name <input name=\"name\" size=\"40\" maxlength=\"128\" ")
            .raw("required value=\"")
            .text(&row.file_name)
            .raw("\"></label><button class=\"primary\">Rename</button></form><p class=\"sub\">")
            .raw("The name becomes a tag: letters, digits, <code>.</code>, <code>_</code> and ")
            .raw("<code>-</code>, any other character made <code>-</code>, a leading path ")
            .raw("dropped, at most 128. ")
            .raw("Each registry holding it is retagged <code>files/")
            .raw(crate::media::DIR)
            .raw(":&lt;name&gt;</code> and its old tag dropped. One that cannot be keeps its ")
            .raw("old tag, shown above; renaming again retries it.</p></details>");
        action_button(h, auth, &m.sha256, "remove", "Remove");
    }
}

fn action_button(h: &mut Html, auth: &Auth, sha256: &str, op: &str, label: &str) {
    h.raw("<form class=\"inline\" method=\"post\" action=\"")
        .text(format!("{}/{op}", detail_path(sha256)))
        .raw("\">");
    csrf_field(h, auth);
    h.raw("<button>").text(label).raw("</button></form>");
}

/// What a form says of a medium.
fn info_of(get: impl Fn(&str) -> Option<String>) -> Result<MediumEdit> {
    let text = |name: &str| get(name).map(|v| v.trim().to_string());
    // Kept as written, but for the CRLF line breaks a browser sends.
    let free = |name: &str| get(name).unwrap_or_default().replace("\r\n", "\n");
    let info = MediumInfo {
        kind: text("kind")
            .filter(|k| !k.is_empty())
            .map(|k| MediumKind::parse(&k))
            .transpose()?
            .unwrap_or_default(),
        sources: text("sources")
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        obtained: text("obtained").unwrap_or_default(),
        product: text("product").unwrap_or_default(),
        edition: text("edition").unwrap_or_default(),
        version: text("version").unwrap_or_default(),
        build: text("build").unwrap_or_default(),
        language: text("language").unwrap_or_default(),
        arch: text("arch").unwrap_or_default(),
        license: text("license")
            .map(|k| LicenseKind::parse(&k))
            .transpose()?
            .unwrap_or_default(),
        license_terms: free("license_terms"),
        renewal: free("renewal"),
        expires: text("expires").unwrap_or_default(),
        notes: free("notes"),
    };
    info.check()?;
    Ok(MediumEdit::whole(info))
}

/// `POST /media/<sha256>/<op>`: edit, rename, approve, unapprove or remove, as the operator
/// session's principal; removal asked first.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
    sha256: &str,
    op: &str,
) -> Result<Response<Body>> {
    let (auth, form) = match super::check_post_sized(req, ui, Role::Operator, MAX_EDIT).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(false, status, text)),
    };
    let hub = ui.hub.clone();
    let sha = sha256.to_string();
    let Some(m) = blocking(move || hub.db.medium(&sha)).await? else {
        return Ok(message(StatusCode::NOT_FOUND, "There is no such medium."));
    };
    let refuse = |e: anyhow::Error| {
        let status = if e.downcast_ref::<crate::store::Stale>().is_some()
            || e.downcast_ref::<crate::media::RenameBusy>().is_some()
        {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        Ok(actions::refused(
            false,
            status,
            &format!(
                "Refused: {}.",
                vk_hub_proto::display_safe(&format!("{e:#}"))
            ),
        ))
    };
    let (hub, principal, sha) = (ui.hub.clone(), auth.session.principal(), sha256.to_string());
    let done = match op {
        "edit" => {
            let edit = match info_of(|k| super::field(&form, k).map(str::to_string)) {
                Ok(edit) => edit,
                Err(e) => return refuse(e),
            };
            let seen = super::field(&form, "was").unwrap_or_default().to_string();
            blocking(move || {
                Ok(crate::media::edit(&hub, &principal, &sha, &edit, Some(&seen)).map(|_| ()))
            })
            .await?
        }
        "rename" => {
            let name = super::field(&form, "name")
                .unwrap_or_default()
                .trim()
                .to_string();
            let seen = super::field(&form, "was").unwrap_or_default().to_string();
            // Held until recorded: an update of the hub would cut it.
            let long = match ui.hub.handover.long_call() {
                Ok(long) => long,
                Err(e) => {
                    let said = format!("Refused: {e:#}.");
                    return Ok(actions::refused(false, StatusCode::CONFLICT, &said));
                }
            };
            // A task of its own, so a browser gone away does not cut it between the registries'
            // retag and its record.
            let renamed = tokio::spawn(async move {
                let _long = long;
                crate::media::rename(&hub, &principal, &sha, &name, Some(&seen))
                    .await
                    .map(|_| ())
            })
            .await
            .context("renaming the medium")?;
            if let Err(e) = &renamed
                && let Some(not) = e.downcast_ref::<crate::media::NotRetagged>()
            {
                return Ok(actions::refused(
                    false,
                    StatusCode::BAD_GATEWAY,
                    &not_retagged(not),
                ));
            }
            renamed
        }
        "approve" | "unapprove" => {
            let approve = op == "approve";
            let done = blocking(move || {
                Ok(crate::media::approve(&hub, &principal, &sha, approve).map(|_| ()))
            })
            .await?;
            if let Err(e) = done {
                return Ok(actions::refused(
                    false,
                    StatusCode::CONFLICT,
                    &approvals_refused(&e, false),
                ));
            }
            Ok(())
        }
        _ => {
            let mut detail = Html::new();
            detail
                .raw("<p>")
                .text(&m.row.file_name)
                .raw(" (<code>")
                .text(crate::store::short(sha256))
                .raw("</code>).</p>");
            let ask = actions::Ask {
                path: format!("{}/remove", detail_path(sha256)),
                back: detail_path(sha256),
                op: "remove".into(),
                what: "Forget this medium and withdraw its approval? The registries keep their \
                       copies; what was said of it here is lost.",
                detail,
                asked: vec![("medium", m.revision()?)],
            };
            if let Some(asked) = actions::ask_first(
                &site.questions,
                super::fleet::layout,
                false,
                &auth,
                &form,
                &ask,
            )? {
                return Ok(asked);
            }
            // Answered for the medium as it is now; removed only if it still is.
            let seen = super::field(&form, "medium")
                .unwrap_or_default()
                .to_string();
            let removed = blocking(move || {
                Ok(crate::media::remove(&hub, &principal, &sha, Some(&seen)).map(|_| ()))
            })
            .await?;
            return match removed {
                Ok(()) => see_other(PATH),
                Err(e) => refuse(e),
            };
        }
    };
    match done {
        Ok(()) => see_other(&detail_path(sha256)),
        Err(e) => refuse(e),
    }
}

/// Report a rename with failed locations still recorded under their previous names.
fn not_retagged(not: &crate::media::NotRetagged) -> String {
    let why = vk_hub_proto::display_safe(&not.why);
    if not.renamed {
        format!("Renamed, but {why}; rename it again to retry.")
    } else {
        format!(
            "Named {} already, but {why}; rename it again to retry.",
            not.name
        )
    }
}

/// Why an approval, or an `upload` to approve, is refused: in the form's words when the list of
/// approved media is full.
fn approvals_refused(e: &anyhow::Error, upload: bool) -> String {
    if e.downcast_ref::<crate::store::ApprovalsFull>().is_none() {
        return format!(
            "Refused: {}.",
            vk_hub_proto::display_safe(&format!("{e:#}"))
        );
    }
    if upload {
        "Refused: the approval list is full. Withdraw an approval, or upload without \
         \u{201c}Approve for jobs fleet-wide\u{201d}."
            .to_string()
    } else {
        "Refused: the approval list is full. Withdraw another approval first.".to_string()
    }
}

/// The upload form's fields before its file, by name, and the file's name.
async fn read_fields<S, E>(
    form: &mut Multipart<S>,
) -> Result<(Vec<(String, String)>, String), Refusal>
where
    S: futures::Stream<Item = Result<Bytes, E>> + Unpin,
{
    const NAMES: &[&str] = &[
        "_csrf",
        "registry",
        "under",
        "approve",
        "kind",
        "product",
        "edition",
        "version",
        "build",
        "language",
        "arch",
        "sources",
        "obtained",
        "license",
        "license_terms",
        "renewal",
        "expires",
        "notes",
    ];
    let mut fields: Vec<(String, String)> = Vec::new();
    loop {
        let Some(part) = form.next_part().await? else {
            return Err(Refusal::Malformed("it carries no file"));
        };
        if part.name == "file" && part.is_file() {
            return Ok((fields, part.filename.unwrap_or_default()));
        }
        if !NAMES.contains(&part.name.as_str()) {
            return Err(Refusal::Malformed("it has a field the form does not"));
        }
        if fields.iter().any(|(k, _)| *k == part.name) {
            return Err(Refusal::Malformed("it has a field twice"));
        }
        let max = match part.name.as_str() {
            // Every source at its longest, a line each.
            "sources" => crate::store::MAX_SOURCES * (crate::store::MAX_URL + 2),
            // A browser sends a text's line breaks as CRLF.
            "license_terms" | "renewal" | "notes" => 2 * MAX_TEXT,
            _ => MAX_TEXT,
        };
        let value = form.text(max).await?;
        fields.push((part.name, value));
    }
}

fn said_of(refusal: &Refusal) -> String {
    match refusal {
        Refusal::TooLarge => "Refused: the upload is longer than it said.".to_string(),
        Refusal::Slow => format!(
            "Refused: the upload was too slow. It must arrive at {}/s or faster, and never \
             pause for {}.",
            pages::bytes(super::operations::MIN_RATE),
            crate::human_duration(super::operations::UPLOAD_IDLE)
        ),
        Refusal::Malformed(why) => format!("Refused: this upload does not match the form: {why}."),
        Refusal::Broken => "The upload broke off.".to_string(),
    }
}

/// The page saying why the registry did not take an upload: its own status when it refused
/// as busy, full or timed out, with when to try again; otherwise a bad gateway.
fn not_sent(e: &anyhow::Error) -> Response<Body> {
    let said = vk_hub_proto::display_safe(&format!("{e:#}"));
    let refused = e.downcast_ref::<crate::media::Refused>();
    let status = refused
        .map(|r| r.status)
        .filter(|s| {
            matches!(
                *s,
                StatusCode::REQUEST_TIMEOUT
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::INSUFFICIENT_STORAGE
            )
        })
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp = actions::refused(false, status, &format!("Refused: {said}."));
    if let Some(secs) = refused.and_then(|r| r.retry_after) {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    }
    resp
}

/// The start of the file part a form is at: at least [`crate::media::HEAD`] bytes, or all of
/// the file if shorter, in the chunks it came in.
struct Head {
    chunks: Vec<Vec<u8>>,
    /// Whether that is all of it.
    whole: bool,
}

impl Head {
    async fn read<S, E>(form: &mut Multipart<S>) -> Result<Head, Refusal>
    where
        S: futures::Stream<Item = Result<Bytes, E>> + Unpin,
    {
        let (mut chunks, mut n) = (Vec::new(), 0);
        while n < crate::media::HEAD {
            let Some(chunk) = form.chunk().await? else {
                return Ok(Head {
                    chunks,
                    whole: true,
                });
            };
            n += chunk.len();
            chunks.push(chunk);
        }
        Ok(Head {
            chunks,
            whole: false,
        })
    }

    /// Its volume label, if the file is an ISO 9660 image.
    fn volume_label(&self) -> Option<String> {
        crate::media::volume_label(&self.chunks.concat())
    }
}

/// Why a file did not reach the registry: the browser's side, or the registry's.
#[derive(Debug)]
enum Failed {
    Browser(Refusal),
    Registry(anyhow::Error),
}

/// Pass the file part `form` is at, `size` bytes starting with `head`, to `send` as a body;
/// what `send` gives, once the form ended right after the file at its declared length. The
/// last chunk is held back until then: a body cut short past the file's last byte must not
/// give the registry the whole file. Whichever side fails first says why.
async fn forward<S, E, T, F>(
    form: &mut Multipart<S>,
    size: u64,
    head: Head,
    send: impl FnOnce(futures::stream::BoxStream<'static, Result<Bytes>>) -> F,
) -> Result<T, Failed>
where
    S: futures::Stream<Item = Result<Bytes, E>> + Unpin,
    F: std::future::Future<Output = Result<T>>,
{
    use futures::StreamExt;
    // The file's chunks go on as they come, a few at a time at most.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(8);
    let body = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (chunk, rx))
    })
    .boxed();
    let feed = async move {
        let mut queued = std::collections::VecDeque::from(head.chunks);
        let mut fed = 0u64;
        let mut held: Option<Vec<u8>> = None;
        let ended = loop {
            let next = match queued.pop_front() {
                Some(chunk) => Ok(Some(chunk)),
                None if head.whole => Ok(None),
                None => form.chunk().await,
            };
            match next {
                Ok(Some(chunk)) => {
                    fed += chunk.len() as u64;
                    if let Some(prev) = held.replace(chunk)
                        && tx.send(Ok(Bytes::from(prev))).await.is_err()
                    {
                        // The registry's side ended, and says why.
                        return Ok(());
                    }
                }
                Ok(None) => {
                    break match form.next_part().await {
                        Ok(None) => form.finish().await,
                        Ok(Some(_)) => Err(Refusal::Malformed("the file is not its last field")),
                        Err(refusal) => Err(refusal),
                    }
                    .and_then(|()| {
                        (fed == size)
                            .then_some(())
                            .ok_or(Refusal::Malformed("the file is not its last field"))
                    });
                }
                Err(refusal) => break Err(refusal),
            }
        };
        // A closed channel means the registry's side ended, and says why.
        match ended {
            Ok(()) => {
                if let Some(last) = held {
                    let _ = tx.send(Ok(Bytes::from(last))).await;
                }
                Ok(())
            }
            Err(refusal) => {
                let _ = tx.send(Err(anyhow!("the browser's upload failed"))).await;
                Err(refusal)
            }
        }
    };
    let sending = send(body);
    tokio::pin!(feed, sending);
    tokio::select! {
        sent = &mut sending => match sent {
            // Every byte went, so the form ended as it must.
            Ok(sent) => feed.await.map(|()| sent).map_err(Failed::Browser),
            Err(e) => Err(Failed::Registry(e)),
        },
        fed = &mut feed => match fed {
            // Dropping the request leaves the registry nothing.
            Err(refusal) => Err(Failed::Browser(refusal)),
            Ok(()) => sending.await.map_err(Failed::Registry),
        },
    }
}

/// `POST /media/upload`: a medium streamed on to the registry, answered with its page once it
/// is recorded, or a page saying why not.
pub(super) async fn upload(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    use super::operations::{MIN_RATE, UPLOAD_GRACE, UPLOAD_IDLE, status_of};
    let refuse = |status: StatusCode, text: &str| Ok(actions::refused(false, status, text));
    let started = tokio::time::Instant::now();
    // Kept to check the session again once the file is in: an upload can outlast it.
    let headers = req.headers().clone();
    let auth = match super::check_caller(&headers, ui, Role::Operator).await? {
        Ok(auth) => auth,
        Err((status, text)) => return refuse(status, text),
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let Some(boundary) = header("content-type").and_then(multipart::boundary) else {
        return refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Refused: upload the medium as multipart/form-data, as the form sends it.",
        );
    };
    let Some(length) = header("content-length").and_then(|l| l.parse::<u64>().ok()) else {
        return refuse(
            StatusCode::LENGTH_REQUIRED,
            "Refused: an upload must say its length.",
        );
    };
    let header_token = header("x-csrf-token").map(str::to_string);
    // The fields first, within what they may take at the rate floor; the file's time comes
    // once they pass.
    let stream = http_body_util::BodyExt::into_data_stream(req.into_body());
    let mut form = Multipart::new(
        stream,
        &boundary,
        length,
        started + UPLOAD_GRACE + Duration::from_secs(FORM_OVERHEAD / MIN_RATE),
        UPLOAD_IDLE,
    );
    let (fields, filename) = match read_fields(&mut form).await {
        Ok(read) => read,
        Err(refusal) => return refuse(status_of(&refusal), &said_of(&refusal)),
    };
    let get = |k: &str| super::field(&fields, k).map(str::to_string);
    if !super::csrf_ok(get("_csrf").or(header_token), &auth) {
        return refuse(StatusCode::FORBIDDEN, super::CSRF_REFUSED);
    }
    let Some(size) = form
        .last_part_len(length)
        .filter(|&n| n > 0 && length - n <= FORM_OVERHEAD)
    else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "Refused: no file was chosen, or the file is not the form's last field.",
        );
    };
    let edit = match info_of(get) {
        // Left blank, the kind, product, version, language and architecture are left to the
        // volume label.
        Ok(edit) => {
            let said = |s: Option<String>| s.filter(|s| !s.is_empty());
            MediumEdit {
                kind: get("kind").filter(|k| !k.is_empty()).and(edit.kind),
                product: said(edit.product),
                version: said(edit.version),
                language: said(edit.language),
                arch: said(edit.arch),
                ..edit
            }
        }
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {said}."));
        }
    };
    let name = match crate::media::tag_name(&filename) {
        Ok(name) => name,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {e:#}.")),
    };
    let mut request = crate::media::Request {
        registry: get("registry").filter(|r| !r.is_empty()),
        under: get("under").filter(|u| !u.trim().is_empty()),
        name: name.clone(),
        approve: get("approve").as_deref() == Some("yes"),
        edit,
    };
    // Taken only now, once the form's fields passed their checks.
    let _slot = match crate::media::slot(&ui.hub) {
        Ok(slot) => slot,
        Err(e) => return refuse(StatusCode::CONFLICT, &format!("Refused: {e:#}.")),
    };
    // Refused now rather than once the registry holds it; the record checks again.
    let (hub, approve) = (ui.hub.clone(), request.approve);
    if let Err(e) = blocking(move || Ok(hub.db.media_room(approve))).await? {
        return refuse(StatusCode::CONFLICT, &approvals_refused(&e, true));
    }
    // Held until the medium is recorded: an update of the hub would cut the upload.
    let _long = match ui.hub.handover.long_call() {
        Ok(long) => long,
        Err(e) => return refuse(StatusCode::CONFLICT, &format!("Refused: {e:#}.")),
    };
    form.set_deadline(started + UPLOAD_GRACE + Duration::from_secs(length / MIN_RATE));
    let (hub, principal) = (ui.hub.clone(), auth.session.principal());
    let (asked, under) = (request.registry.clone(), request.under.clone());
    let target = match blocking(move || {
        Ok(crate::media::target(
            &hub,
            &principal,
            asked.as_deref(),
            under.as_deref(),
            size,
        ))
    })
    .await?
    {
        Ok(target) => target,
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            return refuse(StatusCode::CONFLICT, &format!("Refused: {said}."));
        }
    };
    // What the label tells goes into the annotations, as from the CLI.
    let head = match Head::read(&mut form).await {
        Ok(head) => head,
        Err(refusal) => return refuse(status_of(&refusal), &said_of(&refusal)),
    };
    if let Some(label) = head.volume_label() {
        request.edit = crate::media::guessed(&request.edit, crate::media::from_label(&label));
    }
    let annotations = match request.edit.apply(&MediumInfo::default()) {
        Ok((info, _)) => crate::media::annotations(&info),
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {said}."));
        }
    };
    let sent = match forward(&mut form, size, head, |body| {
        crate::media::send(&target, &name, size, &annotations, body)
    })
    .await
    {
        Ok(sent) => sent,
        Err(Failed::Browser(refusal)) => return refuse(status_of(&refusal), &said_of(&refusal)),
        Err(Failed::Registry(e)) => return Ok(not_sent(&e)),
    };
    // The session may have ended, or lost its role, while the file arrived.
    let auth = match super::check_caller(&headers, ui, Role::Operator).await? {
        Ok(auth) => auth,
        Err((status, text)) => {
            let held = crate::media::held(&target, &name, &sent.put.sha256);
            let said = vk_hub_proto::display_safe(&held);
            return refuse(
                status,
                &format!(
                    "{text} Not recorded: {said}; an operator can upload it again to record it."
                ),
            );
        }
    };
    let (hub, principal) = (ui.hub.clone(), auth.session.principal());
    let recorded = blocking(move || {
        Ok(crate::media::record(
            &hub,
            &principal,
            &target,
            &name,
            &sent,
            &request,
            crate::now_secs(),
        ))
    })
    .await?;
    match recorded {
        Ok(added) if added.known => Ok(known(&auth, &added.medium)),
        Ok(added) => see_other(&detail_path(&added.medium.sha256)),
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            refuse(StatusCode::CONFLICT, &format!("Refused: {said}."))
        }
    }
}

/// The page answering an upload of bytes already known as medium `m`.
fn known(auth: &Auth, m: &Medium) -> Response<Body> {
    let mut h = Html::new();
    h.raw("<h1>Already uploaded</h1><p>This file is <a href=\"")
        .text(detail_path(&m.sha256))
        .raw("\">")
        .text(&m.row.file_name)
        .raw("</a> already. Its description is unchanged; edit it there.</p>");
    super::page(super::fleet::layout("Media", PATH, auth, &h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_name_a_medium_and_an_action() {
        let sha = "ab".repeat(32);
        assert_eq!(detail_target(&detail_path(&sha)), Some(sha.as_str()));
        assert_eq!(detail_target("/media/upload"), None);
        assert_eq!(
            action_target(&format!("/media/{sha}/approve")),
            Some((sha.as_str(), "approve"))
        );
        assert_eq!(
            action_target(&format!("/media/{sha}/rename")),
            Some((sha.as_str(), "rename"))
        );
        assert_eq!(action_target(&format!("/media/{sha}/delete")), None);
        assert_eq!(action_target("/media/upload"), None);
    }

    #[test]
    fn a_form_says_what_a_medium_is() {
        let form = [
            ("kind", "windows"),
            ("product", " Windows Server 2025 "),
            ("sources", "https://a/b\r\n\r\nhttps://c/d\r\n"),
            ("license", "evaluation"),
            ("notes", "line 1\r\nline 2"),
            ("expires", "2027-05-08"),
        ];
        let get = |k: &str| {
            form.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        };
        let edit = info_of(get).unwrap();
        let (info, _) = edit.apply(&MediumInfo::default()).unwrap();
        assert_eq!(info.kind, MediumKind::Windows);
        assert_eq!(info.product, "Windows Server 2025");
        assert_eq!(info.sources, ["https://a/b", "https://c/d"]);
        assert_eq!(info.notes, "line 1\nline 2");
        let bad = |k: &'static str, v: &'static str| move |n: &str| (n == k).then(|| v.to_string());
        assert!(info_of(bad("kind", "iso")).is_err());
        assert!(info_of(bad("expires", "soon")).is_err());
        assert!(info_of(bad("sources", "javascript:alert(1)")).is_err());
    }

    /// The edit form fits its body limit with every field at its longest, every byte
    /// percent-encoded and every line break sent as CRLF.
    #[test]
    fn the_longest_edit_form_fits() {
        use crate::store::{MAX_LINE, MAX_SOURCES, MAX_TEXT, MAX_URL};
        let field = |name: &str, bytes: usize| name.len() + 2 + 3 * bytes;
        let mut len = field("_csrf", 64) + field("was", 16) + field("kind", 16);
        len += field("license", 16);
        for name in ["product", "edition", "version", "build", "language", "arch"] {
            len += field(name, 4 * MAX_LINE);
        }
        for name in ["license_terms", "renewal", "notes"] {
            len += field(name, 2 * MAX_TEXT);
        }
        len += field("sources", MAX_SOURCES * (MAX_URL + 2));
        len += field("obtained", 10) + field("expires", 10);
        assert!(len <= MAX_EDIT, "{len}");
    }

    /// A registry busy, full or timed out is reported with its own status, and when to try
    /// again; anything else as a bad gateway.
    #[test]
    fn a_registry_s_refusal_keeps_its_status() {
        let said = br#"{"errors":[{"code":"DENIED","message":"store is full"}]}"#;
        for (status, retry_after, want) in [
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some(30),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                StatusCode::INSUFFICIENT_STORAGE,
                None,
                StatusCode::INSUFFICIENT_STORAGE,
            ),
            (
                StatusCode::REQUEST_TIMEOUT,
                None,
                StatusCode::REQUEST_TIMEOUT,
            ),
            (StatusCode::UNAUTHORIZED, None, StatusCode::BAD_GATEWAY),
        ] {
            let e = anyhow::Error::from(crate::media::refusal("r1", status, retry_after, said));
            let resp = not_sent(&e);
            assert_eq!(resp.status(), want);
            assert_eq!(
                resp.headers()
                    .get(header::RETRY_AFTER)
                    .map(|v| v.to_str().unwrap().to_string()),
                retry_after.map(|s| s.to_string())
            );
        }
        let resp = not_sent(&anyhow!("registry r1 was not reached in time"));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// A form whose body, `length` bytes, comes as `rx`, read up to its file part's data,
    /// quiet for at most `idle`.
    async fn file_form(
        rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::convert::Infallible>>,
        length: u64,
        idle: Duration,
    ) -> Multipart<impl futures::Stream<Item = Result<Bytes, std::convert::Infallible>> + Unpin>
    {
        let stream = Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|c| (c, rx))
        }));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut form = Multipart::new(stream, "B", length, deadline, idle);
        assert!(form.next_part().await.unwrap().unwrap().is_file());
        form
    }

    const OPEN: &[u8] =
        b"--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\n";
    const CLOSE: &[u8] = b"\r\n--B--\r\n";

    /// What a registry that reads the whole body got of it.
    async fn collect(body: futures::stream::BoxStream<'static, Result<Bytes>>) -> Result<Vec<u8>> {
        use futures::TryStreamExt;
        body.try_fold(Vec::new(), |mut all, c| async move {
            all.extend_from_slice(&c);
            Ok(all)
        })
        .await
    }

    #[tokio::test]
    async fn a_file_goes_on_whole_once_the_form_ends() {
        let file = vec![7u8; 100_000];
        let length = (OPEN.len() + file.len() + CLOSE.len()) as u64;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            for c in [OPEN, &file[..60_000], &file[60_000..], CLOSE] {
                tx.send(Ok(Bytes::copy_from_slice(c))).await.unwrap();
            }
        });
        let mut form = file_form(rx, length, Duration::from_secs(5)).await;
        let head = Head::read(&mut form).await.unwrap();
        let got = forward(&mut form, 100_000, head, collect).await.unwrap();
        assert_eq!(got, vec![7u8; 100_000]);
    }

    /// A body that stops short of its closing boundary's last bytes never gives the registry
    /// the file's last byte.
    #[tokio::test]
    async fn a_form_cut_short_after_its_file_keeps_its_last_chunk() {
        let file = vec![7u8; 100_000];
        let length = (OPEN.len() + file.len() + CLOSE.len()) as u64;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let _tx = tx.clone();
        tokio::spawn(async move {
            let cut = &CLOSE[..CLOSE.len() - 2];
            for c in [OPEN, &file[..60_000], &file[60_000..], cut] {
                tx.send(Ok(Bytes::copy_from_slice(c))).await.unwrap();
            }
        });
        let mut form = file_form(rx, length, Duration::from_millis(300)).await;
        let head = Head::read(&mut form).await.unwrap();
        let got = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = got.clone();
        let failed = forward(&mut form, 100_000, head, |body| async move {
            use futures::StreamExt;
            let mut body = body;
            while let Some(Ok(c)) = body.next().await {
                counted.fetch_add(c.len(), std::sync::atomic::Ordering::SeqCst);
            }
            Err::<(), _>(anyhow!("cut"))
        })
        .await
        .unwrap_err();
        assert!(
            matches!(failed, Failed::Browser(Refusal::Slow)),
            "{failed:?}"
        );
        let got = got.load(std::sync::atomic::Ordering::SeqCst);
        assert!(got < 100_000, "{got}");
    }

    /// A registry that refuses while the browser is still sending is reported at once, as the
    /// registry said.
    #[tokio::test]
    async fn a_registry_s_refusal_is_not_held_up_by_the_browser() {
        let length = (OPEN.len() + 100_000 + CLOSE.len()) as u64;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(Ok(Bytes::copy_from_slice(OPEN))).await.unwrap();
        tx.send(Ok(Bytes::from(vec![7u8; 50_000]))).await.unwrap();
        // The rest never comes; the registry's refusal must not wait on the browser.
        let mut form = file_form(rx, length, Duration::from_secs(60)).await;
        let head = Head::read(&mut form).await.unwrap();
        let failed = tokio::time::timeout(
            Duration::from_secs(5),
            forward(&mut form, 100_000, head, |_body| async {
                Err::<(), _>(anyhow::Error::from(crate::media::refusal(
                    "r1",
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some(30),
                    b"",
                )))
            }),
        )
        .await
        .expect("waited on the browser")
        .unwrap_err();
        let Failed::Registry(e) = failed else {
            panic!("{failed:?}");
        };
        assert_eq!(not_sent(&e).status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(tx);
    }

    /// The registry the fleet-wide setting names, or the only one, is chosen; otherwise the
    /// operator must choose, as from the CLI.
    #[test]
    fn the_registry_to_upload_to_is_chosen_as_the_cli_chooses_it() {
        let able = |ids: &[&str]| -> Vec<(String, String)> {
            ids.iter()
                .map(|id| (id.to_string(), format!("{id}.example")))
                .collect()
        };
        let choose = |able: &[(String, String)], named: Option<&str>| {
            let mut h = Html::new();
            registry_choice(&mut h, able, named);
            h.into_string()
        };
        let must_choose = "<option value=\"\" selected disabled>";
        let one = choose(&able(&["r1"]), None);
        assert!(one.contains("value=\"r1\" selected>") && !one.contains(must_choose));
        let named = choose(&able(&["r1", "r2"]), Some("r2"));
        assert!(named.contains("value=\"r2\" selected>") && !named.contains(must_choose));
        assert!(choose(&able(&["r1", "r2"]), None).contains(must_choose));
        // The named one cannot take it now: another is not chosen in its place.
        assert!(choose(&able(&["r1"]), Some("r9")).contains(must_choose));
    }

    /// A text starting with a line break keeps it once the edit form is shown and posted
    /// back: the browser drops only the line break that follows the tag.
    #[test]
    fn a_text_s_leading_line_break_survives_the_edit_form() {
        let info = MediumInfo {
            notes: "\nindented\n  text ".into(),
            license_terms: "\nterms".into(),
            ..MediumInfo::default()
        };
        let mut h = Html::new();
        info_fields(&mut h, &info, false);
        let page = h.into_string();
        // What a browser posts of a textarea: its text past the one line break HTML drops.
        let posted = |name: &str| {
            let open = format!("<textarea name=\"{name}\"");
            let at = page.find(&open).unwrap();
            let text = &page[at..];
            let text = &text[text.find('>').unwrap() + 1..];
            let text = &text[..text.find("</textarea>").unwrap()];
            text.strip_prefix('\n')
                .unwrap_or(text)
                .replace('\n', "\r\n")
        };
        let get = |k: &str| match k {
            "notes" | "license_terms" => Some(posted(k)),
            _ => None,
        };
        let (back, _) = info_of(get).unwrap().apply(&MediumInfo::default()).unwrap();
        assert_eq!(back.notes, info.notes);
        assert_eq!(back.license_terms, info.license_terms);
    }

    #[test]
    fn a_renewal_date_is_flagged_as_it_nears() {
        let info = |expires: &str| MediumInfo {
            expires: expires.into(),
            ..MediumInfo::default()
        };
        let today = days_of("2026-11-10").unwrap();
        let shown = |i: MediumInfo| {
            let mut h = Html::new();
            renew_by(&mut h, &i, today);
            h.into_string()
        };
        assert!(shown(info("2027-05-08")).ends_with("2027-05-08"));
        assert!(shown(info("2026-11-20")).contains("in 10 days"));
        assert!(shown(info("2026-11-01")).contains("9 days ago"));
        assert_eq!(shown(info("")), "");
    }
}
