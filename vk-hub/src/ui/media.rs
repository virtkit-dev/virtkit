//! Install media ([`crate::media`]): what each is, where it came from, its licence, and where
//! it is.
//!
//! **The list**, `/media`, for any viewer: every medium the hub uploaded, with what it
//! installs, its licence and when it must be renewed, whether jobs may use it and which
//! registries hold it.
//!
//! **A medium's page**, `/media/<sha256>`: everything said of it and where each registry holds
//! it; for an operator, its approval, the form that edits what is said of it, and its removal,
//! confirmed first.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::fleet::FleetSite;
use super::html::Html;
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, message};
use crate::store::{LicenseKind, Medium, MediumEdit, MediumInfo, MediumKind, Role, days_of};

/// The list's path, and the prefix of a medium's page.
pub(super) const PATH: &str = "/media";

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
    (vk_hub_proto::valid_sha256(sha) && matches!(op, "edit" | "approve" | "unapprove" | "remove"))
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
    let media = blocking(move || hub.db.media()).await?;
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

/// The fields that say what a medium is, filled from `i`.
fn info_fields(h: &mut Html, i: &MediumInfo) {
    h.raw("<label>Kind <select name=\"kind\">");
    for k in MediumKind::ALL {
        h.raw("<option value=\"")
            .raw(k.name())
            .raw(if k == i.kind { "\" selected>" } else { "\">" })
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
        info_fields(h, i);
        h.raw("<button class=\"primary\">Save</button></form></details>");
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

/// `POST /media/<sha256>/<op>`: edit, approve, unapprove or remove, as the operator session's
/// principal; removal asked first.
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
        let status = if e.downcast_ref::<crate::store::Stale>().is_some() {
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
                    &approvals_refused(&e),
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

/// Why an approval is refused: in the page's words when the list of approved media is full.
fn approvals_refused(e: &anyhow::Error) -> String {
    if e.downcast_ref::<crate::store::ApprovalsFull>().is_none() {
        return format!(
            "Refused: {}.",
            vk_hub_proto::display_safe(&format!("{e:#}"))
        );
    }
    "Refused: the approval list is full. Withdraw another approval first.".to_string()
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
        info_fields(&mut h, &info);
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
