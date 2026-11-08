//! The CI tools definitions the hub holds, and where each node stands with them.
//!
//! **A definition's page**, `/tools/<sha256>`, for any viewer: what it is, which settings name
//! it, the network each stage of its Dockerfile declares its build reaches, every node kept on
//! it, having it or building it, and the files they installed from it, those that differ
//! between nodes flagged. Operators download it there and remove it, confirmed first.
//!
//! **A node's section** on its page: the tools the settings keep it on, those it has and how
//! they check, its automatic build and, for an operator, the button that builds a failed
//! build's tools now, as `vk-hub nodes tools <id>` does.
//!
//! Operators download the CI tools definitions the hub holds and upload new ones from
//! `/updates`.
//!
//! **A download**, `GET /tools/<sha256>.tar`, is the definition's packed tar as the hub holds
//! it and nodes download it, for operators only: a build context may hold any file.
//!
//! **An upload** is `vk-hub tools add` from a browser: a plain form post, `multipart/form-data`,
//! its CSRF token and label first — checked before the archive is read — then the build context
//! as a tar or a gzipped tar, packed and held as `tools add` packs and holds a directory
//! ([`crate::tools::add_archive`]) and audited as the session's principal. The archive is read
//! into memory, at most [`MAX_UPLOAD`]: one upload at a time, sharing the release upload's slot,
//! under its deadlines.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::fleet::FleetSite;
use super::html::Html;
use super::multipart::{self, Multipart, Refusal};
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, message};
use crate::deploy::{ATTEMPTS, KEY, Named, Standing};
use crate::outputs::{Output, Peers};
use crate::server::Hub;
use crate::store::{NodeRow, Role, SettingsLayers, Tools};
use vk_hub_proto::definition::DeclaredStage;
use vk_hub_proto::{ToolsCheck, ToolsFile, ToolsInstalled, ToolsProgress};

/// Where a definition is uploaded to.
pub(super) const UPLOAD_PATH: &str = "/tools/upload";

/// What a download's path starts with, before `<sha256>.tar`.
const DOWNLOAD_PREFIX: &str = "/tools/";

/// The largest archive uploaded: as large as a definition may be packed, compressed or not.
#[cfg(not(test))]
pub(super) const MAX_UPLOAD: u64 = vk_hub_proto::MAX_TOOLS_DEFINITION;
#[cfg(test)]
pub(super) const MAX_UPLOAD: u64 = 64 * 1024;

/// What a form's other fields and the multipart framing may add to the archive.
const FORM_OVERHEAD: u64 = 64 * 1024;

/// The longest the label may be, as the form sends it.
const MAX_FIELD: usize = 4096;

/// The path of definition `sha256`'s download.
pub(super) fn download_path(sha256: &str) -> String {
    format!("{DOWNLOAD_PREFIX}{sha256}.tar")
}

/// The sha256 a download's `path` names, if it is one: lowercase hex, whole.
pub(super) fn download_target(path: &str) -> Option<&str> {
    let sha = path.strip_prefix(DOWNLOAD_PREFIX)?.strip_suffix(".tar")?;
    vk_hub_proto::valid_sha256(sha).then_some(sha)
}

/// `GET /tools/<sha256>.tar`: the definition's tar, as an attachment named by its label and
/// digest, to an operator.
pub(super) async fn download(auth: &Auth, ui: &Ui, sha256: &str) -> Result<Response<Body>> {
    if auth.session.role < Role::Operator {
        return Ok(message(
            StatusCode::FORBIDDEN,
            "Refused: this needs the operator role.",
        ));
    }
    let hub = ui.hub.clone();
    let sha = sha256.to_string();
    let found = blocking(move || {
        // Held so the definition is not removed between its row and its file.
        let _held = hub.tools_lock();
        let Some(row) = hub.db.tools(&sha)? else {
            return Ok(None);
        };
        let file = crate::tools::path(hub.tools_dir()?, &sha);
        let tar =
            std::fs::read(&file).map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
        Ok(Some((row.version, tar)))
    })
    .await?;
    let Some((version, tar)) = found else {
        return Ok(message(
            StatusCode::NOT_FOUND,
            "There are no such CI tools.",
        ));
    };
    let mut resp = Response::new(Body::Full(Some(bytes::Bytes::from(tar))));
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    // The label passed `check_version`: letters, digits and `. _ - +`, nothing to quote.
    let name = format!(
        "attachment; filename=\"ci-tools-{version}-{}.tar\"",
        crate::store::short(sha256)
    );
    headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&name)?);
    Ok(resp)
}

/// `POST /tools/upload`: a plain form, answered with `/updates` once the definition is held,
/// or a page saying why not.
pub(super) async fn upload(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let refuse = |status: StatusCode, text: &str| Ok(actions::refused(false, status, text));
    // Kept to check the session again once the archive is in: an upload can outlast it.
    let headers = req.headers().clone();
    let auth = match super::check_caller(&headers, ui, Role::Operator).await? {
        Ok(auth) => auth,
        Err((status, text)) => return refuse(status, text),
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let Some(boundary) = header("content-type").and_then(multipart::boundary) else {
        return refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Refused: upload the CI tools as multipart/form-data, as the form sends them.",
        );
    };
    let Some(length) = header("content-length").and_then(|l| l.parse::<u64>().ok()) else {
        return refuse(
            StatusCode::LENGTH_REQUIRED,
            "Refused: an upload must say its length.",
        );
    };
    if length > MAX_UPLOAD.saturating_add(FORM_OVERHEAD) {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, &too_large());
    }
    let header_token = header("x-csrf-token").map(str::to_string);
    let deadline = tokio::time::Instant::now()
        + super::operations::UPLOAD_GRACE
        + Duration::from_secs(length / super::operations::MIN_RATE);
    let stream = http_body_util::BodyExt::into_data_stream(req.into_body());
    let mut form = Multipart::new(
        stream,
        &boundary,
        length,
        deadline,
        super::operations::UPLOAD_IDLE,
    );

    let (csrf, version) = match read_fields(&mut form).await {
        Ok(fields) => fields,
        Err(refusal) => return refuse(status_of(&refusal), &said_of(&refusal)),
    };
    if !super::csrf_ok(csrf.or(header_token), &auth) {
        return refuse(StatusCode::FORBIDDEN, super::CSRF_REFUSED);
    }
    let version = version.unwrap_or_default().trim().to_string();
    if let Err(e) = crate::releases::check_version(&version) {
        return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {e:#}."));
    }
    // Taken only now, by a request that passed every check but the archive's.
    let Some(_slot) = site.uploading.take() else {
        return refuse(
            StatusCode::CONFLICT,
            "Refused: another upload is under way. Wait for it to end.",
        );
    };
    let archive = match receive(&mut form).await {
        Ok(archive) => archive,
        Err(refusal) => {
            if refusal == Refusal::TooLarge {
                // What is left is at most the form's overhead: read, so the browser, still
                // sending, hears why rather than a reset.
                let rest = async { while let Ok(Some(_)) = form.next_part().await {} };
                let _ = tokio::time::timeout(super::operations::UPLOAD_IDLE, rest).await;
            }
            return refuse(status_of(&refusal), &said_of(&refusal));
        }
    };
    if archive.is_empty() {
        return refuse(StatusCode::BAD_REQUEST, "Refused: no file was chosen.");
    }
    // The session may have ended, or lost its role, while the archive arrived.
    let auth = match super::check_caller(&headers, ui, Role::Operator).await? {
        Ok(auth) => auth,
        Err((status, text)) => return refuse(status, text),
    };
    let (hub, principal) = (ui.hub.clone(), auth.session.principal());
    let added = blocking(move || {
        Ok(crate::tools::add_archive(
            &hub, &principal, &archive, &version,
        ))
    })
    .await?;
    if let Err(e) = added {
        let said = vk_hub_proto::display_safe(&format!("{e:#}"));
        return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {said}."));
    }
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_static(super::fleet::UPDATES_PATH),
    );
    Ok(resp)
}

/// The form's CSRF token and label, before its file, which the body is left at.
async fn read_fields<S, E>(
    form: &mut Multipart<S>,
) -> Result<(Option<String>, Option<String>), Refusal>
where
    S: futures::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
{
    let (mut csrf, mut version) = (None, None);
    loop {
        let Some(part) = form.next_part().await? else {
            return Err(Refusal::Malformed("it carries no file"));
        };
        let slot = match part.name.as_str() {
            "file" if part.file => return Ok((csrf, version)),
            "_csrf" => &mut csrf,
            "version" => &mut version,
            _ => return Err(Refusal::Malformed("it has a field the form does not")),
        };
        if slot.is_some() {
            return Err(Refusal::Malformed("it has a field twice"));
        }
        *slot = Some(form.text(MAX_FIELD).await?);
    }
}

/// The file part the body is at, read whole, and the body to its end.
async fn receive<S, E>(form: &mut Multipart<S>) -> Result<Vec<u8>, Refusal>
where
    S: futures::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
{
    let mut archive = Vec::new();
    while let Some(chunk) = form.chunk().await? {
        if (archive.len() + chunk.len()) as u64 > MAX_UPLOAD {
            return Err(Refusal::TooLarge);
        }
        archive.extend_from_slice(&chunk);
    }
    match form.next_part().await? {
        None => Ok(archive),
        Some(_) => Err(Refusal::Malformed("the file is not its last field")),
    }
}

fn too_large() -> String {
    format!(
        "Refused: CI tools are uploaded as an archive of at most {}.",
        pages::bytes(MAX_UPLOAD)
    )
}

fn status_of(refusal: &Refusal) -> StatusCode {
    match refusal {
        Refusal::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        Refusal::Slow => StatusCode::REQUEST_TIMEOUT,
        Refusal::Malformed(_) | Refusal::Broken => StatusCode::BAD_REQUEST,
    }
}

fn said_of(refusal: &Refusal) -> String {
    match refusal {
        Refusal::TooLarge => too_large(),
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

/// The form that uploads CI tools, on an operator's `/updates`, folded behind a button.
pub(super) fn upload_form(h: &mut Html, auth: &Auth) {
    h.raw("<details class=\"upload\"><summary class=\"button\">Add CI tools</summary>")
        .raw("<form class=\"wide\" method=\"post\" action=\"")
        .raw(UPLOAD_PATH)
        .raw("\" enctype=\"multipart/form-data\">");
    // Before the file: the hub checks them before it reads the archive.
    csrf_field(h, auth);
    h.raw("<label>Label <input name=\"version\" required size=\"16\" ")
        .raw("placeholder=\"git-2.56.0\"></label>")
        .raw("<label>Build context <input type=\"file\" name=\"file\" required ")
        .raw("accept=\".tar,.tar.gz,.tgz\"></label>")
        .raw("<button class=\"primary\">Upload</button></form><p class=\"sub\">A tar, or a ")
        .raw("gzipped tar, of at most ")
        .text(pages::bytes(MAX_UPLOAD))
        .raw(" holding a Dockerfile whose <code>tools</code> stage holds the tools, at its ")
        .raw("root or in a single directory. Regular files and directories only. Nodes run ")
        .raw("what it builds in every job that lacks its own tools.</p></details>");
}

/// Where definition `sha256`'s page is.
pub(super) fn detail_path(sha256: &str) -> String {
    format!("{DOWNLOAD_PREFIX}{sha256}")
}

/// The sha256 a definition's page `path` names, if it is one.
pub(super) fn detail_target(path: &str) -> Option<&str> {
    let sha = path.strip_prefix(DOWNLOAD_PREFIX)?;
    vk_hub_proto::valid_sha256(sha).then_some(sha)
}

/// The sha256 whose removal `path` posts to, if it is one: `/tools/<sha256>/remove`.
pub(super) fn remove_target(path: &str) -> Option<&str> {
    let sha = path
        .strip_prefix(DOWNLOAD_PREFIX)?
        .strip_suffix("/remove")?;
    vk_hub_proto::valid_sha256(sha).then_some(sha)
}

/// A definition's label linked to its page, and its short sha256.
fn labelled(h: &mut Html, sha256: &str, label: &str) {
    h.raw("<a href=\"")
        .text(detail_path(sha256))
        .raw("\">")
        .text(label)
        .raw("</a> (<code title=\"")
        .text(sha256)
        .raw("\">")
        .text(crate::store::short(sha256))
        .raw("</code>)");
}

/// Which layer of the settings gives a node its `tools`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Source {
    Node,
    Fleet,
    /// Neither: the default, the built-in tools.
    Default,
}

impl Source {
    fn of(layers: &SettingsLayers, id: &str) -> Source {
        if layers.nodes.get(id).is_some_and(|l| l.contains_key(KEY)) {
            Source::Node
        } else if layers.fleet.contains_key(KEY) {
            Source::Fleet
        } else {
            Source::Default
        }
    }

    fn words(self) -> &'static str {
        match self {
            Source::Node => "by this node's setting",
            Source::Fleet => "by the fleet-wide setting",
            Source::Default => "by default: the tools built into the hub",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Source::Node => "its own setting",
            Source::Fleet => "fleet-wide",
            Source::Default => "by default",
        }
    }
}

/// What the `tools` setting keeps a node on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Kept {
    /// Nothing: its tools are left to operators.
    Left(Source),
    /// Tools the hub does not hold: why.
    Missing(String, Source),
    Tools {
        sha256: String,
        label: String,
        source: Source,
    },
}

/// What a node's page shows of its CI tools.
pub(super) struct NodeTools {
    pub(super) kept: Kept,
    pub(super) standing: Standing,
    pub(super) installed: Option<ToolsInstalled>,
    /// Whether the hub still holds the definition of the tools installed.
    pub(super) installed_held: bool,
    pub(super) peers: Option<Peers>,
    /// Whether a tools build, an update or a reset is still to finish on the node.
    pub(super) busy: bool,
}

/// What node `id` of row `row`, `connected` or not, shows of its CI tools, `peers` comparing
/// its files with other nodes'.
pub(super) fn read_node(
    hub: &Hub,
    id: &str,
    row: &NodeRow,
    connected: bool,
    peers: Option<Peers>,
) -> Result<NodeTools> {
    let layers = hub.db.settings_layers()?;
    let source = Source::of(&layers, id);
    let named = Named::of(layers.merged(id).get(KEY));
    let builtin = &crate::tools::builtin().packed.sha256;
    let wanted = hub.db.tools_wanted(id, builtin)?;
    let kept = match &wanted {
        None => Kept::Left(source),
        Some(Err(why)) => Kept::Missing(why.clone(), source),
        Some(Ok((sha256, row))) => Kept::Tools {
            sha256: sha256.clone(),
            label: row.version.clone(),
            source,
        },
    };
    let deploys = hub.db.tools_deploys()?;
    let standing = crate::deploy::standing(
        &named,
        match &wanted {
            Some(Ok((sha, row))) => Ok((sha.as_str(), row.version.as_str())),
            Some(Err(why)) => Err(why.as_str()),
            None => Err(""),
        },
        deploys.get(id),
        row,
        connected,
    );
    let installed = row
        .inventory
        .as_ref()
        .and_then(|i| i.versions.tools.clone());
    let installed_held = match &installed {
        Some(t) => hub.db.tools(&t.sha256)?.is_some(),
        None => false,
    };
    Ok(NodeTools {
        kept,
        standing,
        installed,
        installed_held,
        peers,
        busy: hub.db.tools_busy(id, crate::now_secs())?,
    })
}

/// A node's tools against what they were when installed, in words, with a badge.
fn check(h: &mut Html, check: Option<&ToolsCheck>) {
    match check {
        Some(ToolsCheck::Intact) => {
            h.raw("<span class=\"badge ok\">intact</span> as when they were installed")
        }
        Some(ToolsCheck::Modified { entries }) => h
            .raw("<span class=\"badge bad\">changed</span> since they were installed: ")
            .node(&entries.join(", "))
            .raw(". The node gives them to no job and builds them anew."),
        Some(ToolsCheck::Unrecorded) => h.raw(
            "<span class=\"badge warn\">unchecked</span> installed with no checksums to check \
             them against. The node builds them anew.",
        ),
        None => h.raw("not checked by this node"),
    };
}

/// What `standing` says of the automatic build, given `now`; `None` when there is none to
/// speak of.
fn standing_html(standing: &Standing, now: u64) -> Option<Html> {
    let mut h = Html::new();
    match standing {
        Standing::Settled => return None,
        Standing::Unavailable(why) => {
            h.raw("cannot start: ").text(why);
        }
        Standing::Building { attempt, since, .. } => {
            h.raw("<span class=\"badge busy\">building</span> attempt ")
                .text(attempt)
                .raw(" of ")
                .text(ATTEMPTS)
                .raw(", asked ");
            super::fleet::time_ago(&mut h, now, *since);
        }
        Standing::Built { .. } => {
            h.raw("built; waiting for the node to report them");
        }
        Standing::Failed {
            reason,
            attempt,
            at,
            retry_at,
            held,
        } => {
            h.raw("<span class=\"badge bad\">failed</span> attempt ")
                .text(attempt)
                .raw(" of ")
                .text(ATTEMPTS)
                .raw(", ");
            super::fleet::time_ago(&mut h, now, *at);
            h.raw(": ").node(reason).raw(". ");
            match (retry_at, held) {
                (Some(t), _) if *t > now => {
                    h.raw("The next attempt is due after ");
                    pages::at(&mut h, *t);
                    h.raw(".");
                }
                (Some(_), Some(why)) => {
                    h.raw("The next attempt is due, and waits: ")
                        .text(why)
                        .raw(".");
                }
                (Some(_), None) => {
                    h.raw("The next attempt is due.");
                }
                (None, _) => {
                    h.raw("No more attempts are made on their own.");
                }
            }
        }
        Standing::Due => {
            h.raw("due to start");
        }
        Standing::Held(why) => {
            h.raw("not started: ").text(why);
        }
    }
    Some(h)
}

/// A list a node reported, or `none`.
fn listed(h: &mut Html, items: &[String]) {
    if items.is_empty() {
        h.raw("none");
    } else {
        h.node(&items.join(", "));
    }
}

/// One entry of installed tools in a table's cells: its sha256 and size, or the file it links
/// to; `flagged` when it is not what another node or the check found.
fn file_row(h: &mut Html, name: &str, file: &ToolsFile, flagged: bool) {
    h.raw("<tr><td><code>").node(name).raw("</code>");
    if flagged {
        h.raw(" <span class=\"badge bad\">differs</span>");
    }
    h.raw("</td>");
    match file {
        ToolsFile::File { sha256, size } => {
            h.raw("<td><code title=\"")
                .node(sha256)
                .raw("\">")
                .node(crate::store::short(sha256))
                .raw("</code></td><td>")
                .text(pages::bytes(*size))
                .raw("</td>");
        }
        ToolsFile::Link { target } => {
            h.raw("<td colspan=\"2\">link to <code>")
                .node(target)
                .raw("</code></td>");
        }
    }
    h.raw("</tr>");
}

/// `files`, those of `flagged` marked.
fn files_table(h: &mut Html, files: &BTreeMap<String, ToolsFile>, flagged: &[&str]) {
    h.raw("<table class=\"grid\"><thead><tr><th>file</th><th>sha256</th><th>size</th>")
        .raw("</tr></thead><tbody>");
    for (name, file) in files {
        file_row(h, name, file, flagged.contains(&name.as_str()));
    }
    h.raw("</tbody></table>");
}

/// A node page's CI tools section for node `id`; with an operator's `csrf`, on a node that can
/// be steered (`steer`), the button that builds a failed build's tools now.
pub(super) fn node_section(
    h: &mut Html,
    t: &NodeTools,
    id: &str,
    csrf: Option<&str>,
    steer: bool,
    now: u64,
) {
    h.raw("<section><h2>CI tools</h2><table class=\"kv\"><tbody><tr><th>Kept on</th><td>");
    match &t.kept {
        Kept::Left(source) => {
            h.raw("none: its tools are left to operators, ")
                .raw(source.words());
        }
        Kept::Missing(why, source) => {
            h.raw("none the hub holds, ")
                .raw(source.words())
                .raw(": ")
                .text(why);
        }
        Kept::Tools {
            sha256,
            label,
            source,
        } => {
            labelled(h, sha256, label);
            h.raw(", ").raw(source.words());
        }
    }
    h.raw(" · <a href=\"")
        .raw(super::settings::PATH)
        .raw("\">settings</a></td></tr>");
    if let Some(html) = standing_html(&t.standing, now) {
        pages::kv_html(h, "Automatic build", &html);
    }
    match &t.installed {
        None => pages::kv(h, "Installed", "none from the hub"),
        Some(i) => {
            h.raw("<tr><th>Installed</th><td>");
            if t.installed_held {
                labelled(h, &i.sha256, &i.version);
            } else {
                h.node(&i.version)
                    .raw(" (<code>")
                    .node(crate::store::short(&i.sha256))
                    .raw("</code>), which the hub no longer holds");
            }
            if !i.in_use {
                h.raw(", not in use: <code>[executor] tools_dir</code> names another directory");
            }
            h.raw("</td></tr><tr><th>Check</th><td>");
            check(h, i.check.as_ref());
            h.raw("</td></tr>");
            // Both the node's words: a tool's name is a file it found.
            for (name, version) in &i.tools {
                h.raw("<tr><th>")
                    .node(name)
                    .raw("</th><td>")
                    .node(version)
                    .raw("</td></tr>");
            }
            h.raw("<tr><th>Its build reached</th><td>");
            match &i.egress {
                None => {
                    h.raw("not reported");
                }
                Some(e) => {
                    listed(h, &e.contacted);
                    if !e.refused.is_empty() {
                        h.raw("; refused ");
                        listed(h, &e.refused);
                    }
                }
            }
            h.raw("</td></tr>");
            if let Some(p) = &t.peers {
                h.raw("<tr><th>Other nodes</th><td>");
                if p.differ.is_empty() {
                    h.raw("<span class=\"badge ok\">same files</span> as ")
                        .text(p.same)
                        .raw(" other node(s) with these tools");
                } else {
                    h.raw("<span class=\"badge bad\">other files</span> than ");
                    for (n, d) in p.differ.iter().enumerate() {
                        if n > 0 {
                            h.raw(", ");
                        }
                        h.raw("<a href=\"/node/")
                            .text(&d.id)
                            .raw("\">")
                            .node(&d.hostname)
                            .raw("</a>");
                    }
                    h.raw(": ").node(&p.differing().join(", "));
                    if p.same > 0 {
                        h.raw("; the same as ").text(p.same).raw(" other node(s)");
                    }
                }
                h.raw("</td></tr>");
            }
        }
    }
    h.raw("</tbody></table>");
    if let Some(i) = t.installed.as_ref().filter(|i| !i.files.is_empty()) {
        let mut flagged: Vec<&str> = t.peers.as_ref().map(Peers::differing).unwrap_or_default();
        if let Some(ToolsCheck::Modified { entries }) = &i.check {
            flagged.extend(entries.iter().map(String::as_str));
        }
        h.raw("<details><summary>Files as installed (")
            .text(i.files.len())
            .raw(")</summary>");
        files_table(h, &i.files, &flagged);
        h.raw("</details>");
    }
    if let (Some(csrf), true, Kept::Tools { sha256, .. }) = (csrf, steer, &t.kept)
        && matches!(t.standing, Standing::Failed { held: None, .. })
        && !t.busy
    {
        super::fleet::form_open(h, &format!("/node/{id}/action"), csrf);
        h.raw("<input type=\"hidden\" name=\"op\" value=\"tools\">")
            .raw("<input type=\"hidden\" name=\"tools\" value=\"")
            .text(sha256)
            .raw("\"><button>Build now</button><span class=\"does\">Build these CI tools on ")
            .raw("this node now. Automatic attempts count again from this one.</span></form>");
    }
    h.raw("</section>");
}

/// A node with something to do with a definition: kept on it, having it, or building it.
struct DefinitionNode {
    id: String,
    hostname: String,
    /// Where its setting names the definition from; `None` when it does not.
    kept: Option<Source>,
    installed: Option<ToolsInstalled>,
    /// Against the definition, when it is kept on it.
    standing: Option<Standing>,
    /// Its latest build of the definition.
    progress: Option<ToolsProgress>,
}

/// What a definition's page shows.
struct Definition {
    tools: Tools,
    builtin: bool,
    /// Whether the fleet-wide setting names it: `Some(true)` by being unset, for the built-in.
    fleet: Option<bool>,
    /// The nodes whose own setting names it, by ID and hostname.
    named: Vec<(String, String)>,
    declared: Result<Vec<DeclaredStage>, String>,
    nodes: Vec<DefinitionNode>,
    /// What the nodes installed from it, most reported first.
    outputs: Vec<Output>,
    hostnames: BTreeMap<String, String>,
}

impl Definition {
    fn kept_on(&self) -> usize {
        self.nodes.iter().filter(|n| n.kept.is_some()).count()
    }

    fn installed_on(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| {
                n.installed
                    .as_ref()
                    .is_some_and(|i| i.sha256 == self.tools.sha256)
            })
            .count()
    }
}

fn read_definition(hub: &Hub, sha256: &str) -> Result<Option<Definition>> {
    let Some(row) = hub.db.tools(sha256)? else {
        return Ok(None);
    };
    let builtin_sha = &crate::tools::builtin().packed.sha256;
    let builtin = sha256 == builtin_sha;
    let layers = hub.db.settings_layers()?;
    let names = |layer: &crate::store::SettingsLayer| {
        layer
            .get(KEY)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|v| v == sha256 || (builtin && v == crate::deploy::BUILTIN))
    };
    let fleet = if names(&layers.fleet) {
        Some(false)
    } else {
        (builtin && !layers.fleet.contains_key(KEY)).then_some(true)
    };
    let nodes = hub.db.nodes()?;
    let hostnames: BTreeMap<String, String> = nodes
        .iter()
        .map(|(id, row)| (id.clone(), row.hostname.clone()))
        .collect();
    let named = layers
        .nodes
        .iter()
        .filter(|(_, l)| names(l))
        .map(|(id, _)| {
            let host = hostnames.get(id).cloned().unwrap_or_else(|| id.clone());
            (id.clone(), host)
        })
        .collect();
    let declared = crate::tools::dockerfile(hub.tools_dir()?, sha256)
        .map_err(|e| format!("{e:#}"))
        .and_then(|text| vk_hub_proto::definition::declared_egress(&text));
    let deploys = hub.db.tools_deploys()?;
    let mut shown = Vec::new();
    for (id, node) in &nodes {
        let named = Named::of(layers.merged(id).get(KEY));
        let kept = named.sha256(builtin_sha) == Some(sha256);
        let installed = node
            .inventory
            .as_ref()
            .and_then(|i| i.versions.tools.clone());
        let deploy = deploys.get(id).filter(|d| d.sha256() == sha256);
        let progress = node
            .report
            .as_ref()
            .and_then(|r| r.tools.clone())
            .filter(|p| p.sha256 == sha256);
        let has = installed.as_ref().is_some_and(|i| i.sha256 == sha256);
        if !(kept || has || deploy.is_some() || progress.is_some()) {
            continue;
        }
        let connected = hub.reach(id) == crate::server::Reach::Connected;
        shown.push(DefinitionNode {
            id: id.clone(),
            hostname: node.hostname.clone(),
            kept: kept.then(|| Source::of(&layers, id)),
            installed,
            standing: kept.then(|| {
                crate::deploy::standing(
                    &named,
                    Ok((sha256, row.version.as_str())),
                    deploys.get(id),
                    node,
                    connected,
                )
            }),
            progress,
        });
    }
    shown.sort_by(|a, b| (&a.hostname, &a.id).cmp(&(&b.hostname, &b.id)));
    let outputs = crate::ops::tools_outputs(&nodes)
        .remove(sha256)
        .map(|d| d.outputs)
        .unwrap_or_default();
    Ok(Some(Definition {
        tools: Tools {
            sha256: sha256.to_string(),
            row,
        },
        builtin,
        fleet,
        named,
        declared,
        nodes: shown,
        outputs,
        hostnames,
    }))
}

/// `GET /tools/<sha256>`: the definition's page.
pub(super) async fn detail(auth: &Auth, ui: &Ui, sha256: &str) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let sha = sha256.to_string();
    let Some(def) = blocking(move || read_definition(&hub, &sha)).await? else {
        return Ok(message(
            StatusCode::NOT_FOUND,
            "There are no such CI tools.",
        ));
    };
    let csrf = (auth.session.role >= Role::Operator).then_some(auth.csrf.as_str());
    let main = definition_page(&def, csrf, crate::now_secs());
    let title = def.tools.row.version.clone();
    Ok(super::page(super::fleet::layout(
        &title,
        super::fleet::UPDATES_PATH,
        auth,
        &main,
    )))
}

/// Definition `d`'s page; with an operator's `csrf`, its download and removal.
fn definition_page(d: &Definition, csrf: Option<&str>, now: u64) -> Html {
    let sha = &d.tools.sha256;
    let row = &d.tools.row;
    let mut h = Html::new();
    h.raw("<h1>")
        .text(&row.version)
        .raw("</h1><p class=\"sub\">CI tools <code>")
        .text(sha)
        .raw("</code>");
    if d.builtin {
        h.raw(" · built into the hub");
    }
    h.raw(" · <a href=\"")
        .raw(super::fleet::UPDATES_PATH)
        .raw("\">Back to updates</a></p>");

    pages::section(&mut h, "Definition");
    pages::kv(
        &mut h,
        "Build context",
        &format!("{} file(s), {}", row.files, pages::bytes(row.size)),
    );
    let mut added = pages::at_html(row.added_at);
    added.raw(" by ").text(&row.added_by);
    pages::kv_html(&mut h, "Added", &added);
    let mut named = Html::new();
    match d.fleet {
        Some(true) => {
            named.raw("fleet-wide, by default");
        }
        Some(false) => {
            named.raw("fleet-wide");
        }
        None => {}
    }
    for (n, (id, host)) in d.named.iter().enumerate() {
        if n > 0 || d.fleet.is_some() {
            named.raw(", ");
        }
        named
            .raw("<a href=\"/node/")
            .text(id)
            .raw("\">")
            .node(host)
            .raw("</a>");
    }
    if d.fleet.is_none() && d.named.is_empty() {
        named.raw("none");
    }
    pages::kv_html(&mut h, "Named by the settings", &named);
    pages::kv(&mut h, "Kept on", &format!("{} node(s)", d.kept_on()));
    pages::kv(
        &mut h,
        "Installed on",
        &format!("{} node(s)", d.installed_on()),
    );
    h.raw("</tbody></table>");
    if let Some(csrf) = csrf {
        h.raw("<p class=\"actions\"><a class=\"button\" href=\"")
            .text(download_path(sha))
            .raw("\" download>Download</a></p>");
        if !d.builtin && d.fleet.is_none() && d.named.is_empty() {
            h.raw("<form class=\"act\" method=\"post\" action=\"")
                .text(remove_path(sha))
                .raw("\">");
            pages::csrf_input(&mut h, csrf);
            h.raw("<input type=\"hidden\" name=\"op\" value=\"remove\">")
                .raw("<button class=\"danger\">Remove</button><span class=\"does\">Remove ")
                .raw("these CI tools from the hub. Nodes keep the tools they installed.")
                .raw("</span></form>");
        }
    }
    h.raw("</section>");

    h.raw("<section><h2>Network its build declares</h2>");
    match &d.declared {
        Err(why) => {
            h.raw("<p class=\"empty\">Unknown: its Dockerfile cannot be read: ")
                .text(why)
                .raw(".</p>");
        }
        Ok(stages) => {
            h.raw("<table class=\"grid\"><thead><tr><th>stage</th><th>host names</th>")
                .raw("<th>addresses</th></tr></thead><tbody>");
            for s in stages {
                h.raw("<tr><td><code>").text(&s.name).raw("</code></td>");
                match &s.egress {
                    None => h.raw("<td colspan=\"2\">none: its steps reach no network</td>"),
                    Some(e) => {
                        h.raw("<td>");
                        listed(&mut h, &e.names);
                        h.raw("</td><td>");
                        listed(&mut h, &e.ips);
                        h.raw("</td>")
                    }
                };
                h.raw("</tr>");
            }
            h.raw("</tbody></table><p class=\"sub\">A node holds each stage's steps to what ")
                .raw("it declares, within the node's own limits on what builds reach.</p>");
        }
    }
    h.raw("</section>");

    h.raw("<section><h2>Nodes</h2>");
    if d.nodes.is_empty() {
        h.raw("<p class=\"empty\">No node is kept on these tools, has them, or built them.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>node</th><th>kept on them</th>")
            .raw("<th>installed</th><th>automatic build</th><th>latest build</th>")
            .raw("<th>files</th><th>its build reached</th></tr></thead><tbody>");
        for n in &d.nodes {
            definition_node(&mut h, d, n, now);
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section>");

    h.raw("<section><h2>Files as installed</h2>");
    if d.outputs.is_empty() {
        h.raw("<p class=\"empty\">No node has reported the files it installed from them.</p>");
    }
    for (n, o) in d.outputs.iter().enumerate() {
        let mut flagged: Vec<&str> = Vec::new();
        for (m, other) in d.outputs.iter().enumerate() {
            if m != n {
                flagged.extend(
                    crate::outputs::differing(&o.files, &other.files)
                        .into_iter()
                        .filter_map(|e| o.files.get_key_value(&e).map(|(k, _)| k.as_str())),
                );
            }
        }
        flagged.sort_unstable();
        flagged.dedup();
        h.raw("<h3>Files <code>")
            .text(crate::store::short(&o.digest))
            .raw("</code>, reported by ");
        for (m, id) in o.nodes.iter().enumerate() {
            if m > 0 {
                h.raw(", ");
            }
            h.raw("<a href=\"/node/")
                .text(id)
                .raw("\">")
                .node(d.hostnames.get(id).map_or(id.as_str(), String::as_str))
                .raw("</a>");
        }
        h.raw("</h3>");
        files_table(&mut h, &o.files, &flagged);
    }
    if d.outputs.len() > 1 {
        h.raw("<p class=\"sub\">Nodes reported other files from the same definition. Which ")
            .raw("are right cannot be told from the reports alone.</p>");
    }
    h.raw("</section>");
    h
}

/// Node `n`'s row of definition `d`'s nodes.
fn definition_node(h: &mut Html, d: &Definition, n: &DefinitionNode, now: u64) {
    let sha = &d.tools.sha256;
    h.raw("<tr><td><a href=\"/node/")
        .text(&n.id)
        .raw("\">")
        .node(&n.hostname)
        .raw("</a></td><td>")
        .raw(n.kept.map_or("no", Source::short))
        .raw("</td><td>");
    let this = n.installed.as_ref().filter(|i| i.sha256 == *sha);
    match (&n.installed, this) {
        (_, Some(i)) => check(h, i.check.as_ref()),
        (Some(other), None) => {
            h.raw("other tools: ")
                .node(&other.version)
                .raw(" (<code>")
                .node(crate::store::short(&other.sha256))
                .raw("</code>)");
        }
        (None, None) => {
            h.raw("none");
        }
    }
    h.raw("</td><td>");
    match n.standing.as_ref().and_then(|s| standing_html(s, now)) {
        Some(html) => h.html(&html),
        None => h.raw("-"),
    };
    h.raw("</td><td>");
    match &n.progress {
        Some(p) => {
            h.raw(crate::store::tools_phase_name(p.phase));
            if let Some(m) = &p.message {
                h.raw(": ").node(m);
            }
        }
        None => {
            h.raw("-");
        }
    }
    h.raw("</td><td>");
    match this {
        Some(i) if i.files.is_empty() => {
            h.raw("not recorded");
        }
        Some(_) => match d.outputs.iter().find(|o| o.nodes.contains(&n.id)) {
            Some(o) => {
                h.raw("<code>")
                    .text(crate::store::short(&o.digest))
                    .raw("</code>");
            }
            None => {
                h.raw("-");
            }
        },
        None => {
            h.raw("-");
        }
    }
    h.raw("</td><td>");
    match this.map(|i| &i.egress) {
        Some(Some(e)) => {
            listed(h, &e.contacted);
            if !e.refused.is_empty() {
                h.raw("; refused ");
                listed(h, &e.refused);
            }
        }
        Some(None) => {
            h.raw("not reported");
        }
        None => {
            h.raw("-");
        }
    }
    h.raw("</td></tr>");
}

/// Where definition `sha256`'s removal posts.
fn remove_path(sha256: &str) -> String {
    format!("{DOWNLOAD_PREFIX}{sha256}/remove")
}

/// `POST /tools/<sha256>/remove`: confirmed first, then [`crate::tools::remove`] as the
/// operator's principal, which refuses tools built in, named by a setting or still to be built
/// by a node; back to `/updates` once done.
pub(super) async fn remove(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
    sha256: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let hub = ui.hub.clone();
    let sha = sha256.to_string();
    let Some(row) = blocking(move || hub.db.tools(&sha)).await? else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There are no such CI tools.",
        ));
    };
    let mut detail = Html::new();
    detail
        .raw("<p>CI tools ")
        .text(&row.version)
        .raw(" (<code>")
        .text(crate::store::short(sha256))
        .raw("</code>).</p>");
    let ask = actions::Ask {
        path: remove_path(sha256),
        back: detail_path(sha256),
        op: "remove".into(),
        what: "Remove these CI tools from the hub? Nodes keep the tools they installed, but no \
               node can build them again until they are added anew.",
        detail,
        asked: Vec::new(),
    };
    if let Some(asked) = actions::ask_first(
        &site.questions,
        super::fleet::layout,
        htmx,
        &auth,
        &form,
        &ask,
    )? {
        return Ok(asked);
    }
    let (hub, principal, sha) = (ui.hub.clone(), auth.session.principal(), sha256.to_string());
    let removed = blocking(move || Ok(crate::tools::remove(&hub, &principal, &sha))).await?;
    match removed {
        Ok(true) => {}
        Ok(false) => {
            return Ok(actions::refused(
                htmx,
                StatusCode::NOT_FOUND,
                "There are no such CI tools.",
            ));
        }
        Err(e) => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {e:#}."),
            ));
        }
    }
    if htmx {
        return Ok(super::fleet::said_so(&format!(
            "Removed the CI tools {}.",
            row.version
        )));
    }
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_static(super::fleet::UPDATES_PATH),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outputs::Differ;
    use crate::store::ToolsRow;
    use vk_hub_proto::ToolsEgress;
    use vk_hub_proto::definition::DeclaredEgress;

    const NOW: u64 = 1_000_000;

    fn files(git: &str) -> BTreeMap<String, ToolsFile> {
        BTreeMap::from([
            (
                "git".to_string(),
                ToolsFile::File {
                    sha256: git.repeat(64),
                    size: 2048,
                },
            ),
            (
                "git-remote-https".to_string(),
                ToolsFile::Link {
                    target: "git-remote-http".into(),
                },
            ),
        ])
    }

    fn installed(sha: &str, check: Option<ToolsCheck>) -> ToolsInstalled {
        ToolsInstalled {
            sha256: sha.into(),
            version: "git-2".into(),
            tools: BTreeMap::from([("git".into(), "git version 2.56.0".into())]),
            in_use: true,
            files: files("1"),
            egress: Some(ToolsEgress {
                contacted: vec!["cache.nixos.org".into()],
                refused: vec![],
            }),
            check,
        }
    }

    fn failed(held: Option<&str>, retry_at: Option<u64>) -> Standing {
        Standing::Failed {
            reason: "the build failed: refused to example.org".into(),
            attempt: 2,
            at: NOW - 60,
            retry_at,
            held: held.map(str::to_string),
        }
    }

    fn node(standing: Standing, installed: Option<ToolsInstalled>, busy: bool) -> NodeTools {
        NodeTools {
            kept: Kept::Tools {
                sha256: "ab".repeat(32),
                label: "git-2".into(),
                source: Source::Fleet,
            },
            standing,
            installed,
            installed_held: true,
            peers: None,
            busy,
        }
    }

    fn render(t: &NodeTools, csrf: Option<&str>, steer: bool) -> String {
        let mut h = Html::new();
        node_section(&mut h, t, "n1", csrf, steer, NOW);
        h.into_string()
    }

    #[test]
    fn a_failed_build_is_shown_with_its_next_attempt_and_built_now_by_an_operator() {
        let sha = "ab".repeat(32);
        let t = node(failed(None, Some(NOW + 600)), None, false);
        let page = render(&t, Some("tok"), true);
        assert!(
            page.contains(&format!("href=\"/tools/{sha}\">git-2</a>")),
            "{page}"
        );
        assert!(page.contains("by the fleet-wide setting"), "{page}");
        assert!(page.contains("<span class=\"badge bad\">failed</span> attempt 2 of 5"));
        assert!(page.contains("refused to example.org"), "{page}");
        assert!(page.contains("The next attempt is due after"), "{page}");
        assert!(page.contains("none from the hub"), "{page}");
        assert!(
            page.contains(&format!(
                "action=\"/node/n1/action\" hx-post=\"/node/n1/action\" hx-swap=\"none\">\
                 <input type=\"hidden\" name=\"_csrf\" value=\"tok\"><input type=\"hidden\" \
                 name=\"op\" value=\"tools\"><input type=\"hidden\" name=\"tools\" \
                 value=\"{sha}\"><button>Build now</button>"
            )),
            "{page}"
        );
        // Not to a viewer, nor on a node that cannot be steered, has a build or an update
        // under way, or waits for something else.
        assert!(!render(&t, None, true).contains("Build now"));
        assert!(!render(&t, Some("tok"), false).contains("Build now"));
        let busy = node(failed(None, Some(NOW + 600)), None, true);
        assert!(!render(&busy, Some("tok"), true).contains("Build now"));
        let held = node(
            failed(Some("it is not connected"), Some(NOW - 1)),
            None,
            false,
        );
        let page = render(&held, Some("tok"), true);
        assert!(!page.contains("Build now"));
        assert!(page.contains("The next attempt is due, and waits: it is not connected."));
        let spent = render(&node(failed(None, None), None, false), None, true);
        assert!(
            spent.contains("No more attempts are made on their own."),
            "{spent}"
        );
        let building = Standing::Building {
            command: "c1".into(),
            attempt: 3,
            since: NOW - 30,
        };
        let page = render(&node(building, None, true), Some("tok"), true);
        assert!(page.contains("<span class=\"badge busy\">building</span> attempt 3 of 5"));
        assert!(!page.contains("Build now"));
    }

    #[test]
    fn installed_tools_show_their_check_their_build_s_network_and_how_they_compare() {
        let sha = "ab".repeat(32);
        let modified = ToolsCheck::Modified {
            entries: vec!["git".into()],
        };
        let mut t = node(Standing::Due, Some(installed(&sha, Some(modified))), false);
        t.peers = Some(Peers {
            same: 1,
            differ: vec![Differ {
                id: "n3".into(),
                hostname: "host-3".into(),
                entries: vec!["git-remote-https".into()],
            }],
        });
        let page = render(&t, None, true);
        assert!(
            page.contains(
                "<span class=\"badge bad\">changed</span> since they were \
                               installed: git."
            ),
            "{page}"
        );
        assert!(page.contains("<tr><th>Its build reached</th><td>cache.nixos.org</td></tr>"));
        assert!(
            page.contains(
                "other files</span> than <a href=\"/node/n3\">host-3</a>: \
                               git-remote-https; the same as 1 other node(s)"
            ),
            "{page}"
        );
        assert!(
            page.contains("<summary>Files as installed (2)</summary>"),
            "{page}"
        );
        // Both the entry the check found changed and the one another node differs in.
        assert_eq!(page.matches("badge bad\">differs").count(), 2, "{page}");
        assert!(
            page.contains("link to <code>git-remote-http</code>"),
            "{page}"
        );
        assert!(page.contains("<tr><th>git</th><td>git version 2.56.0</td></tr>"));
        assert!(page.contains("due to start"), "{page}");

        let mut t = node(
            Standing::Settled,
            Some(installed(&sha, Some(ToolsCheck::Intact))),
            false,
        );
        t.installed_held = false;
        t.installed.as_mut().unwrap().egress = None;
        let page = render(&t, None, true);
        assert!(
            page.contains("<span class=\"badge ok\">intact</span>"),
            "{page}"
        );
        assert!(page.contains("which the hub no longer holds"), "{page}");
        assert!(page.contains("<td>not reported</td>"), "{page}");
        assert!(!page.contains("Automatic build"), "{page}");

        let mut t = node(Standing::Settled, None, false);
        t.kept = Kept::Left(Source::Node);
        assert!(
            render(&t, None, true)
                .contains("none: its tools are left to operators, by this node's setting")
        );
    }

    fn definition(
        outputs: Vec<Output>,
        declared: Result<Vec<DeclaredStage>, String>,
    ) -> Definition {
        let sha = "cd".repeat(32);
        Definition {
            tools: Tools {
                sha256: sha.clone(),
                row: ToolsRow {
                    version: "e2e-good".into(),
                    size: 10240,
                    files: 2,
                    added_at: NOW - 3600,
                    added_by: "uid 0".into(),
                },
            },
            builtin: false,
            fleet: None,
            named: vec![("n1".into(), "host-1".into())],
            declared,
            nodes: vec![
                DefinitionNode {
                    id: "n1".into(),
                    hostname: "host-1".into(),
                    kept: Some(Source::Node),
                    installed: Some(installed(&sha, Some(ToolsCheck::Intact))),
                    standing: Some(Standing::Settled),
                    progress: None,
                },
                DefinitionNode {
                    id: "n2".into(),
                    hostname: "host-2".into(),
                    kept: None,
                    installed: Some(installed(&"ef".repeat(32), None)),
                    standing: None,
                    progress: Some(ToolsProgress {
                        command: "c".into(),
                        version: "e2e-good".into(),
                        sha256: sha.clone(),
                        phase: vk_hub_proto::ToolsPhase::Failed,
                        message: Some("vk build failed".into()),
                        log: vec![],
                    }),
                },
            ],
            outputs,
            hostnames: BTreeMap::from([
                ("n1".into(), "host-1".into()),
                ("n2".into(), "host-2".into()),
            ]),
        }
    }

    #[test]
    fn a_definition_s_page_shows_its_network_its_nodes_and_their_files() {
        let declared = vec![
            DeclaredStage {
                name: "fetch".into(),
                egress: Some(DeclaredEgress {
                    ips: vec!["192.0.2.1".into()],
                    names: vec!["cache.nixos.org".into(), "github.com".into()],
                }),
            },
            DeclaredStage {
                name: "tools".into(),
                egress: None,
            },
        ];
        let one = Output {
            digest: "11".repeat(32),
            files: files("1"),
            nodes: vec!["n1".into()],
        };
        let other = Output {
            digest: "22".repeat(32),
            files: files("2"),
            nodes: vec!["n2".into()],
        };
        let d = definition(vec![one, other], Ok(declared));
        let page = definition_page(&d, None, NOW).into_string();
        assert!(page.contains("<h1>e2e-good</h1>"), "{page}");
        assert!(
            page.contains("<tr><th>Named by the settings</th><td><a href=\"/node/n1\">host-1</a>")
        );
        assert!(
            page.contains("<tr><th>Kept on</th><td>1 node(s)</td>"),
            "{page}"
        );
        assert!(
            page.contains("<tr><th>Installed on</th><td>1 node(s)</td>"),
            "{page}"
        );
        assert!(
            page.contains(
                "<td><code>fetch</code></td><td>cache.nixos.org, github.com</td><td>192.0.2.1</td>"
            ),
            "{page}"
        );
        assert!(
            page.contains(
                "<td><code>tools</code></td><td colspan=\"2\">none: its steps reach no network</td>"
            ),
            "{page}"
        );
        // No download nor removal for a viewer.
        assert!(
            !page.contains("Download") && !page.contains("Remove"),
            "{page}"
        );
        assert!(page.contains("<td>its own setting</td><td><span class=\"badge ok\">intact"));
        assert!(page.contains("<td>no</td><td>other tools: git-2"), "{page}");
        assert!(page.contains("<td>failed: vk build failed</td>"), "{page}");
        assert!(page.contains(&format!(
            "<code>{}</code></td><td>cache.nixos.org</td>",
            "11".repeat(6)
        )));
        // Two groups of files, each flagging git, the entry they differ in.
        assert_eq!(page.matches("<h3>Files <code>").count(), 2, "{page}");
        assert_eq!(page.matches("badge bad\">differs").count(), 2, "{page}");
        assert!(page.contains("Which are right cannot be told"), "{page}");

        // A definition named by a setting cannot be removed; one named by none can.
        let page = definition_page(&d, Some("tok"), NOW).into_string();
        assert!(page.contains("download>Download</a>"), "{page}");
        assert!(!page.contains("Remove"), "{page}");
        let mut free = definition(Vec::new(), Err("it holds no Dockerfile".into()));
        free.named.clear();
        let page = definition_page(&free, Some("tok"), NOW).into_string();
        assert!(
            page.contains(&format!(
                "action=\"/tools/{}/remove\"><input type=\"hidden\" name=\"_csrf\" value=\"tok\">\
             <input type=\"hidden\" name=\"op\" value=\"remove\"><button \
             class=\"danger\">Remove</button>",
                "cd".repeat(32)
            )),
            "{page}"
        );
        assert!(page.contains("Unknown: its Dockerfile cannot be read: it holds no Dockerfile."));
        assert!(page.contains("No node has reported the files"), "{page}");
        free.builtin = true;
        assert!(
            !definition_page(&free, Some("tok"), NOW)
                .into_string()
                .contains("Remove")
        );
    }
}
