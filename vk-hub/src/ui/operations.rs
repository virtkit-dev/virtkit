//! Operators upload releases, fetch them from GitHub ([`crate::fetch`]) and start rollouts
//! from `/operations`, alongside controls for active rollouts. Starting a rollout requires
//! confirmation of its plan ([`actions::ask_first`]). Each uses the admin socket's operations
//! — `release add`'s checks, `release fetch`, `rollout create` — as the session's principal.
//!
//! **An upload** is a plain form post, `multipart/form-data` read as it arrives
//! ([`multipart`]): the CSRF token, the version and the signature come first — and are checked
//! before a byte of the file is written — then the file, streamed to a private file in the
//! releases directory, which is removed on any failure, the client leaving included. The
//! body may be at most [`MAX_UPLOAD`] past its form fields, must say its length, and must
//! arrive within [`UPLOAD_GRACE`] plus its length at [`MIN_RATE`], never going quiet for
//! [`UPLOAD_IDLE`]: the 10 seconds a form has would cut off any binary. One upload at a time,
//! counted from when its fields pass; the session is checked again once the file is in.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use futures::Stream;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::fleet::{FleetSite, layout, said_so};
use super::html::Html;
use super::multipart::{self, Multipart, Refusal};
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, field};
use crate::fetch::{self, FetchStatus, Phase};
use crate::ops::{self, NodeView, RolloutPlan, Selection};
use crate::releases;
use crate::rollout::{NodeStatus, RolloutNode};
use crate::store::{Release, Role};

/// Where a release is uploaded to.
pub(super) const UPLOAD_PATH: &str = "/releases/upload";
/// Where a fetch is asked for.
pub(super) const FETCH_PATH: &str = "/releases/fetch";
/// Where a rollout is started.
pub(super) const ROLLOUT_PATH: &str = "/rollouts";

/// The largest binary uploaded: the largest a release may be.
#[cfg(not(test))]
pub(super) const MAX_UPLOAD: u64 = releases::MAX_RELEASE;
#[cfg(test)]
pub(super) const MAX_UPLOAD: u64 = 64 * 1024;

/// What a form's other fields and the multipart framing may add to the file.
const FORM_OVERHEAD: u64 = 64 * 1024;

/// The slowest an upload may arrive on average: 2 Mbit/s, so a gigabyte has a little over an
/// hour and a release of a hundred megabytes under seven minutes.
const MIN_RATE: u64 = 256 * 1024;

/// What an upload has on top of its length at [`MIN_RATE`]: a slow start, a TLS handshake.
const UPLOAD_GRACE: Duration = Duration::from_secs(60);

/// The longest an upload may go without a byte arriving.
#[cfg(not(test))]
const UPLOAD_IDLE: Duration = Duration::from_secs(30);
#[cfg(test)]
const UPLOAD_IDLE: Duration = Duration::from_secs(1);

/// The longest a field of the upload form may be: a signature, base64.
const MAX_FIELD: usize = 4096;

/// Whether an upload is under way.
pub(super) struct Uploading(AtomicBool);

impl Uploading {
    pub(super) fn new() -> Self {
        Uploading(AtomicBool::new(false))
    }

    /// The slot, if no upload holds it; given back when dropped.
    fn take(&self) -> Option<UploadSlot<'_>> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| UploadSlot(&self.0))
    }
}

struct UploadSlot<'a>(&'a AtomicBool);

impl Drop for UploadSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// `POST /releases/upload`: a plain form, answered with `/operations` once the release is
/// held, or a page saying why not.
pub(super) async fn upload(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let refuse = |status: StatusCode, text: &str| Ok(actions::refused(false, status, text));
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
            "Refused: a release is uploaded as multipart/form-data, as the form sends it.",
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
    let deadline =
        tokio::time::Instant::now() + UPLOAD_GRACE + Duration::from_secs(length / MIN_RATE);
    let stream = http_body_util::BodyExt::into_data_stream(req.into_body());
    let mut form = Multipart::new(stream, &boundary, length, deadline, UPLOAD_IDLE);

    let fields = match read_fields(&mut form).await {
        Ok(fields) => fields,
        Err(refusal) => return refuse(status_of(&refusal), &said_of(&refusal)),
    };
    if !super::csrf_ok(fields.csrf.or(header_token), &auth) {
        return refuse(StatusCode::FORBIDDEN, super::CSRF_REFUSED);
    }
    let version = fields.version.unwrap_or_default().trim().to_string();
    if let Err(e) = releases::check_version(&version) {
        return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {e:#}."));
    }
    let signature = fields.signature.filter(|s| !s.trim().is_empty());
    if let Some(Err(e)) = signature.as_deref().map(releases::check_signature) {
        return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {e:#}."));
    }

    // Taken only now, by a request that passed every check but the file's: one that fails
    // them holds nothing while it trickles in.
    let Some(_slot) = site.uploading.take() else {
        return refuse(
            StatusCode::CONFLICT,
            "Refused: another release is being uploaded; wait for it to end.",
        );
    };
    let hub = ui.hub.clone();
    let (staged, file) = blocking(move || releases::Staged::create(&hub, "upload")).await?;
    let size = match receive(&mut form, file).await? {
        Ok(size) => size,
        Err(refusal) => {
            if refusal == Refusal::TooLarge {
                // What is left is at most the form's overhead: read, so the browser, still
                // sending, hears why rather than a reset.
                let rest = async { while let Ok(Some(_)) = form.next_part().await {} };
                let _ = tokio::time::timeout(UPLOAD_IDLE, rest).await;
            }
            return refuse(status_of(&refusal), &said_of(&refusal));
        }
    };
    if size == 0 {
        return refuse(StatusCode::BAD_REQUEST, "Refused: no file was chosen.");
    }
    // The session may have ended, or lost its role, while the file arrived.
    let auth = match super::check_caller(&headers, ui, Role::Operator).await? {
        Ok(auth) => auth,
        Err((status, text)) => return refuse(status, text),
    };
    let (hub, principal) = (ui.hub.clone(), auth.session.principal());
    let added = blocking(move || {
        Ok(releases::adopt(
            &hub, &principal, staged, &version, signature,
        ))
    })
    .await?;
    if let Err(e) = added {
        let said = vk_hub_proto::display_safe(&format!("{e:#}"));
        return refuse(StatusCode::BAD_REQUEST, &format!("Refused: {said}."));
    }
    Ok(back_to_operations())
}

/// The upload form's fields before its file, which the body is left at.
#[derive(Default)]
struct Fields {
    csrf: Option<String>,
    version: Option<String>,
    signature: Option<String>,
}

async fn read_fields<S, E>(form: &mut Multipart<S>) -> Result<Fields, Refusal>
where
    S: Stream<Item = Result<bytes::Bytes, E>> + Unpin,
{
    let mut fields = Fields::default();
    loop {
        let Some(part) = form.next_part().await? else {
            return Err(Refusal::Malformed("it carries no file"));
        };
        let slot = match part.name.as_str() {
            "file" if part.file => return Ok(fields),
            "_csrf" => &mut fields.csrf,
            "version" => &mut fields.version,
            "signature" => &mut fields.signature,
            _ => return Err(Refusal::Malformed("it has a field the form does not")),
        };
        if slot.is_some() {
            return Err(Refusal::Malformed("it has a field twice"));
        }
        *slot = Some(form.text(MAX_FIELD).await?);
    }
}

/// Write the file part the body is at to `file`, flushed to disk, and read to the end of the
/// body: its size, or why it is refused.
async fn receive<S, E>(form: &mut Multipart<S>, file: std::fs::File) -> Result<Result<u64, Refusal>>
where
    S: Stream<Item = Result<bytes::Bytes, E>> + Unpin,
{
    let mut out = tokio::fs::File::from_std(file);
    let mut size = 0u64;
    loop {
        let chunk = match form.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(refusal) => return Ok(Err(refusal)),
        };
        size = size.saturating_add(chunk.len() as u64);
        if size > MAX_UPLOAD {
            return Ok(Err(Refusal::TooLarge));
        }
        out.write_all(&chunk).await?;
    }
    match form.next_part().await {
        Ok(None) => {}
        Ok(Some(_)) => return Ok(Err(Refusal::Malformed("the file is not its last field"))),
        Err(refusal) => return Ok(Err(refusal)),
    }
    out.sync_all().await?;
    Ok(Ok(size))
}

fn too_large() -> String {
    format!(
        "Refused: a release is at most {}.",
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
            "Refused: the upload was too slow; it has to arrive at {}/s or faster, and never \
             pause for {}.",
            pages::bytes(MIN_RATE),
            crate::human_duration(UPLOAD_IDLE)
        ),
        Refusal::Malformed(why) => format!("Refused: this is not the form's upload: {why}."),
        Refusal::Broken => "The upload broke off.".to_string(),
    }
}

fn back_to_operations() -> Response<Body> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/operations"));
    resp
}

/// For htmx, `said` in the flash; else back to `/operations`.
fn done(htmx: bool, said: &str) -> Response<Body> {
    if htmx {
        said_so(said)
    } else {
        back_to_operations()
    }
}

/// `POST /releases/fetch`: `op=fetch` starts fetching `version` (or the latest) in the
/// background, which `/operations` follows; `op=check` asks the repository which release is
/// the latest.
pub(super) async fn fetch_action(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let Some(source) = ui.hub.fetches.source().map(|s| s.url().to_string()) else {
        return Ok(actions::refused(
            htmx,
            StatusCode::CONFLICT,
            "Refused: fetching releases is off on this hub (release_repository = \"none\").",
        ));
    };
    match field(&form, "op") {
        Some("check") => match fetch::latest(&ui.hub).await {
            Ok(version) => Ok(done(
                htmx,
                &format!("The latest release of {source} is {version}."),
            )),
            Err(e) => {
                let said = vk_hub_proto::display_safe(&format!("{e:#}"));
                Ok(actions::refused(
                    htmx,
                    StatusCode::BAD_GATEWAY,
                    &format!("Asking {source} failed: {said}."),
                ))
            }
        },
        Some("fetch") => {
            let version = match fetch::wanted(field(&form, "version").unwrap_or("")) {
                Ok(version) => version,
                Err(e) => {
                    return Ok(actions::refused(
                        htmx,
                        StatusCode::BAD_REQUEST,
                        &format!("Refused: {e:#}."),
                    ));
                }
            };
            let what = version.clone().unwrap_or_else(|| "latest".into());
            let (hub, principal) = (ui.hub.clone(), auth.session.principal());
            // Dropped, not awaited: the fetch runs on, and the page follows it.
            let started =
                blocking(move || Ok(fetch::start(&hub, &principal, version).map(drop))).await?;
            match started {
                Ok(()) => Ok(done(
                    htmx,
                    &format!(
                        "Fetching vk {what} from {source}; how it goes shows below and in the \
                         audit log."
                    ),
                )),
                Err(e) => Ok(actions::refused(
                    htmx,
                    StatusCode::CONFLICT,
                    &format!("Refused: {e:#}."),
                )),
            }
        }
        _ => Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "No such action.",
        )),
    }
}

/// `POST /rollouts`: an operator starting a rollout, once they have answered the question
/// saying which nodes it updates in which waves — from the same session, once, and only while
/// that is still what it would do.
pub(super) async fn create_rollout(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let plan = match rollout_plan(&form) {
        Ok(plan) => plan,
        Err(why) => {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                &format!("Refused: {why}."),
            ));
        }
    };
    let (hub, asked_plan) = (ui.hub.clone(), plan.clone());
    let planned = blocking(move || Ok(ops::plan_rollout(&hub, &asked_plan))).await?;
    let (release, nodes) = match planned {
        Ok(planned) => planned,
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {said}."),
            ));
        }
    };
    let ask = actions::Ask {
        path: ROLLOUT_PATH.to_string(),
        back: "/operations".to_string(),
        op: "create".to_string(),
        what: "Start this rollout? Each wave's nodes drain, update and come back before the \
               next wave starts.",
        detail: plan_detail(&plan, &release, &nodes),
        asked: asked(&plan, &release, &nodes),
    };
    if let Some(asked) = actions::ask_first(&site.questions, layout, htmx, &auth, &form, &ask)? {
        return Ok(asked);
    }
    let (hub, principal) = (ui.hub.clone(), auth.session.principal());
    let started =
        blocking(move || Ok(ops::start_rollout(&hub, &principal, &plan, &release, nodes))).await?;
    match started {
        Ok(r) => Ok(done(
            htmx,
            &format!(
                "Started rollout {} of vk {}; it shows below.",
                crate::rollout::short_id(&r.id),
                r.row.version
            ),
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

/// The rollout `form` asks for: the form's own fields, or a question's answer, which carries
/// the nodes as one field.
fn rollout_plan(form: &[(String, String)]) -> Result<RolloutPlan, String> {
    let release = field(form, "release").unwrap_or("");
    if vk_hub_proto::from_hex_lower::<32>(release).is_none() {
        return Err("choose a release".into());
    }
    let ids = |ids: Vec<&str>| -> Result<Selection, String> {
        let mut out: Vec<String> = Vec::new();
        for id in ids {
            if !vk_hub_proto::valid_id(id) {
                return Err("a node is not one of the hub's".into());
            }
            if !out.iter().any(|o| o == id) {
                out.push(id.to_string());
            }
        }
        if out.is_empty() {
            return Err("choose at least one node, or all".into());
        }
        Ok(Selection::Nodes(out))
    };
    let nodes = match (field(form, "nodes"), field(form, "select")) {
        (Some("all"), _) | (None, Some("all")) => Selection::All,
        (Some(list), _) => ids(list.split(',').collect())?,
        (None, Some("some")) => ids(form
            .iter()
            .filter(|(k, _)| k == "node")
            .map(|(_, v)| v.as_str())
            .collect())?,
        (None, _) => return Err("choose the nodes".into()),
    };
    let number = |name: &str, what: &str| -> Result<u32, String> {
        field(form, name)
            .unwrap_or("")
            .trim()
            .parse()
            .map_err(|_| format!("{what} is a whole number"))
    };
    let window = |name: &str, what: &str| -> Result<u64, String> {
        crate::parse_window(field(form, name).unwrap_or("").trim())
            .map(|d| d.as_secs())
            .map_err(|e| format!("{what}: {e}"))
    };
    let yes = |name: &str| field(form, name) == Some("yes");
    Ok(RolloutPlan {
        release: release.to_string(),
        nodes,
        batch: number("batch", "the batch")?,
        canary_per_profile: yes("canary_per_profile"),
        max_failures: number("max_failures", "the failures to absorb")?,
        node_timeout_secs: window("node_timeout", "the node timeout")?,
        drain_timeout_secs: window("drain_timeout", "the drain timeout")?,
        force: yes("force"),
    })
}

/// What a rollout's question is asked about, as the fields of its answer: the plan, and the
/// nodes by wave it comes to now, as a digest — a node enrolled, removed or updated meanwhile
/// changes what the answer would start.
fn asked(plan: &RolloutPlan, release: &Release, nodes: &[RolloutNode]) -> actions::Asked {
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_string();
    let mut digest = Sha256::new();
    for n in nodes {
        digest.update(format!("{}\0{}\0{:?}\n", n.id, n.wave, n.status).as_bytes());
    }
    vec![
        ("release", release.sha256.clone()),
        (
            "nodes",
            match &plan.nodes {
                Selection::All => "all".to_string(),
                Selection::Nodes(ids) => ids.join(","),
            },
        ),
        ("batch", plan.batch.to_string()),
        ("canary_per_profile", yes_no(plan.canary_per_profile)),
        ("max_failures", plan.max_failures.to_string()),
        ("node_timeout", format!("{}s", plan.node_timeout_secs)),
        ("drain_timeout", format!("{}s", plan.drain_timeout_secs)),
        ("force", yes_no(plan.force)),
        ("plan", vk_hub_proto::to_hex(&digest.finalize())),
    ]
}

/// What the rollout would do: the release, its nodes wave by wave, and those it skips.
fn plan_detail(plan: &RolloutPlan, release: &Release, nodes: &[RolloutNode]) -> Html {
    let to_update: Vec<&RolloutNode> = nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Pending)
        .collect();
    let waves = to_update
        .iter()
        .map(|n| n.wave)
        .max()
        .map_or(0, |w| w.saturating_add(1));
    let mut h = Html::new();
    h.raw("<p>vk ")
        .text(&release.row.version)
        .raw(" (<code>")
        .text(crate::store::short(&release.sha256))
        .raw("</code>")
        .raw(if release.row.signature.is_some() {
            ", signed"
        } else {
            ", unsigned: a node that requires signed releases refuses it"
        })
        .raw(") to ")
        .text(to_update.len())
        .raw(" node(s) in ")
        .text(waves)
        .raw(" wave(s)")
        .raw(if plan.canary_per_profile {
            ", one node of each hardware profile first"
        } else {
            ""
        })
        .raw(", batches of ")
        .text(plan.batch)
        .raw(". It pauses at a failure, and aborts past ")
        .text(plan.max_failures)
        .raw(". A node has ")
        .text(crate::human_duration(Duration::from_secs(
            plan.drain_timeout_secs,
        )))
        .raw(" to drain and then ")
        .text(crate::human_duration(Duration::from_secs(
            plan.node_timeout_secs,
        )))
        .raw(" to update")
        .raw(if plan.force {
            "; a node whose runner is external is updated without a drain"
        } else {
            ""
        })
        .raw(".</p><ul>");
    for wave in 0..waves {
        h.raw("<li>wave ").text(wave).raw(": ");
        for (i, n) in to_update.iter().filter(|n| n.wave == wave).enumerate() {
            if i > 0 {
                h.raw(", ");
            }
            h.node(&n.hostname);
        }
        h.raw("</li>");
    }
    for n in nodes {
        if let NodeStatus::Skipped { reason } = &n.status {
            h.raw("<li>skipped: ")
                .node(&n.hostname)
                .raw(", ")
                .node(reason)
                .raw("</li>");
        }
    }
    h.raw("</ul>");
    h
}

/// An operator's forms on `/operations`, outside the live fragment so an update never clears
/// one being filled in: upload a release, fetch one, start a rollout.
pub(super) fn forms(
    h: &mut Html,
    auth: &Auth,
    releases: &[Release],
    nodes: &[NodeView],
    source: Option<&str>,
) {
    h.raw("<section><h2>Add a release</h2><form class=\"wide\" method=\"post\" action=\"")
        .raw(UPLOAD_PATH)
        .raw("\" enctype=\"multipart/form-data\">");
    // Before the file: the hub checks them before it writes a byte of it.
    csrf_field(h, auth);
    h.raw("<label>Version <input name=\"version\" required size=\"10\" ")
        .raw("placeholder=\"0.85.0\"></label>")
        .raw("<label>Signature <input name=\"signature\" size=\"24\" ")
        .raw("placeholder=\"optional: vk release-key sign\"></label>")
        .raw("<label>vk binary <input type=\"file\" name=\"file\" required></label>")
        .raw("<button class=\"primary\">Upload</button></form><p class=\"sub\">At most ")
        .text(pages::bytes(MAX_UPLOAD))
        .raw(", sent at ")
        .text(pages::bytes(MIN_RATE))
        .raw(
            "/s or faster. The hub checks that it is an x86-64 ELF holding the version as a \
               string of its own; the node runs it.</p>",
        );
    if let Some(source) = source {
        h.raw("<form class=\"wide\" method=\"post\" action=\"")
            .raw(FETCH_PATH)
            .raw("\" hx-post=\"")
            .raw(FETCH_PATH)
            .raw("\" hx-swap=\"none\">");
        csrf_field(h, auth);
        h.raw("<label>Version <input name=\"version\" value=\"latest\" size=\"10\"></label>")
            .raw("<button name=\"op\" value=\"fetch\">Fetch from GitHub</button>")
            .raw("<button name=\"op\" value=\"check\">Check the latest</button></form>")
            .raw("<p class=\"sub\">From <code>")
            .text(source)
            .raw(
                "</code>: its vk is held once it hashes to the sha256 published beside it, \
                   unsigned.</p>",
            );
    }
    h.raw("</section><section><h2>Start a rollout</h2>");
    if releases.is_empty() || nodes.is_empty() {
        h.raw("<p class=\"empty\">")
            .raw(if releases.is_empty() {
                "Add a release first."
            } else {
                "No node has enrolled yet."
            })
            .raw("</p></section>");
        return;
    }
    h.raw("<form class=\"wide\" method=\"post\" action=\"")
        .raw(ROLLOUT_PATH)
        .raw("\" hx-post=\"")
        .raw(ROLLOUT_PATH)
        .raw("\" hx-swap=\"none\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"create\">")
        .raw("<label>Release <select name=\"release\" required>");
    for r in releases {
        h.raw("<option value=\"")
            .text(&r.sha256)
            .raw("\">vk ")
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
    h.raw("</select></label><fieldset><legend>Nodes</legend>")
        .raw("<label><input type=\"radio\" name=\"select\" value=\"all\" checked> All</label>")
        .raw("<label><input type=\"radio\" name=\"select\" value=\"some\"> Only:</label>");
    for n in nodes.iter().filter(|n| vk_hub_proto::valid_id(&n.id)) {
        h.raw("<label><input type=\"checkbox\" name=\"node\" value=\"")
            .text(&n.id)
            .raw("\"> ")
            .node(&n.hostname)
            .raw("</label>");
    }
    h.raw("</fieldset>")
        .raw("<label>Batch <input type=\"number\" name=\"batch\" min=\"1\" value=\"1\" ")
        .raw("required size=\"4\"></label>")
        .raw("<label><input type=\"checkbox\" name=\"canary_per_profile\" value=\"yes\"> ")
        .raw("A canary per hardware profile first</label>")
        .raw("<label>Failures to absorb <input type=\"number\" name=\"max_failures\" ")
        .raw("min=\"0\" value=\"0\" required size=\"4\"></label>")
        .raw("<label>Node timeout <input name=\"node_timeout\" value=\"30m\" required ")
        .raw("size=\"5\"></label>")
        .raw("<label>Drain timeout <input name=\"drain_timeout\" value=\"4h\" required ")
        .raw("size=\"5\"></label>")
        .raw("<label><input type=\"checkbox\" name=\"force\" value=\"yes\"> ")
        .raw("Include external runners, without a drain</label>")
        .raw("<button class=\"primary\">Start rollout</button></form></section>");
}

/// The fetch under way or last ended, and the latest release last asked about: a line of
/// `/operations`' live fragment.
pub(super) fn fetch_line(
    h: &mut Html,
    status: Option<&FetchStatus>,
    latest: Option<&(String, u64)>,
) {
    if status.is_none() && latest.is_none() {
        return;
    }
    h.raw("<p class=\"sub\">");
    if let Some((version, at)) = latest {
        h.raw("Latest on GitHub: vk ")
            .node(version)
            .raw(", as of ")
            .html(&pages::at_html(*at))
            .raw(". ");
    }
    if let Some(s) = status {
        let asked = s.asked.as_deref().unwrap_or("latest");
        match &s.phase {
            Phase::Resolving => {
                h.raw("Fetching vk ")
                    .text(asked)
                    .raw(": asking which release it is");
            }
            Phase::Downloading { version } => {
                h.raw("Fetching vk ")
                    .text(asked)
                    .raw(": downloading and checking ")
                    .node(version);
            }
            Phase::Done {
                version,
                sha256,
                at,
            } => {
                h.raw("Fetched vk ")
                    .node(version)
                    .raw(" (<code>")
                    .text(crate::store::short(sha256))
                    .raw("</code>) at ")
                    .html(&pages::at_html(*at));
            }
            Phase::Failed { reason, at } => {
                h.raw("<span class=\"reason\">Fetching vk ")
                    .text(asked)
                    .raw(" failed</span> at ")
                    .html(&pages::at_html(*at))
                    .raw(": ")
                    .node(reason);
            }
        }
        h.raw(", asked by ").text(&s.by).raw(".");
    }
    h.raw("</p>");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_rollout_form_and_its_answer_ask_the_same() {
        let sha = "ab".repeat(32);
        let (a, b) = ("12".repeat(16), "34".repeat(16));
        let asked = rollout_plan(&form(&[
            ("release", &sha),
            ("select", "some"),
            ("node", &a),
            ("node", &b),
            ("node", &a),
            ("batch", "2"),
            ("canary_per_profile", "yes"),
            ("max_failures", "1"),
            ("node_timeout", "30m"),
            ("drain_timeout", "4h"),
        ]))
        .unwrap();
        assert_eq!(asked.nodes, Selection::Nodes(vec![a.clone(), b.clone()]));
        assert_eq!(
            (asked.node_timeout_secs, asked.drain_timeout_secs),
            (1800, 14_400)
        );
        assert!(asked.canary_per_profile && !asked.force);
        let answer = rollout_plan(&form(&[
            ("release", &sha),
            ("nodes", &format!("{a},{b}")),
            ("batch", "2"),
            ("canary_per_profile", "yes"),
            ("max_failures", "1"),
            ("node_timeout", "1800s"),
            ("drain_timeout", "14400s"),
            ("force", "no"),
        ]))
        .unwrap();
        assert_eq!(asked, answer);
        for bad in [
            vec![("release", "ab")],
            vec![("release", sha.as_str()), ("select", "some")],
            vec![("release", sha.as_str()), ("nodes", "zz")],
            vec![
                ("release", sha.as_str()),
                ("select", "all"),
                ("batch", "x"),
                ("max_failures", "0"),
                ("node_timeout", "30m"),
                ("drain_timeout", "4h"),
            ],
            vec![
                ("release", sha.as_str()),
                ("select", "all"),
                ("batch", "1"),
                ("max_failures", "0"),
                ("node_timeout", "10s"),
                ("drain_timeout", "4h"),
            ],
        ] {
            assert!(rollout_plan(&form(&bad)).is_err(), "{bad:?}");
        }
    }
}
