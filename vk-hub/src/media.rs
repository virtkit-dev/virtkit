//! Install media — Windows ISOs, driver ISOs — uploaded through the hub to a registry it
//! manages, approved for jobs, and described for the operators who keep them
//! (`docs/fleet-design.md`, *Install media*).
//!
//! `vk-hub media add` streams a file from the hub's host to the registry's file put
//! ([`vk_hub_proto::registry::FILES_PATH`]), hashing it without keeping a copy. The registry
//! stores it as `vk registry put --keep --dir win-media` would: tagged
//! `files/sha256:<sha256>`, where nodes' Windows builds fetch media by digest, and
//! `files/win-media:<name>`, with upload-time metadata as annotations. The hub records the
//! medium and approves it in the fleet-wide `executor.windows_media` unless asked not to,
//! only after the registry confirms the sha256 the hub computed. A registry that is not
//! connected, does not take file puts or hub tokens, has no URL bound, uses plain http off
//! loopback, or last reported too little space is refused before uploading. The registry
//! also refuses uploads when busy or short of space. An incomplete body leaves nothing
//! behind on either side. If the registry stored the file but the hub could not record it,
//! the error says so; uploading it again after fixing the cause records it.
//!
//! The hub writes as `hub:media`, with a token it mints itself, audited, for the registry
//! alone, granting writes under the two repositories' prefixes, and living as long as an
//! upload may. One upload runs at a time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use vk_hub_proto::registry::{
    FILE_ANNOTATIONS_HEADER, FILE_RETENTION_HEADER, FILES_PATH, FilePut, RETENTION_KEEP,
};
use vk_hub_proto::token::Grant;

use crate::server::{Hub, Reach};
use crate::store::{Location, Medium, MediumAdded, MediumEdit, MediumInfo, MediumKind, MediumRow};

/// The `files/` directory media are named in, as `vk registry put --dir` names it.
pub const DIR: &str = "win-media";

/// The token's subject.
const SUBJECT: &str = "hub:media";

/// The longest a token lives, and an upload with it: past a medium's upload over a slow link.
pub(crate) const TOKEN_TTL: Duration = Duration::from_secs(12 * 3600);

/// What the registry must have free past the medium.
const HEADROOM: u64 = 1 << 30;

/// The most of the registry's answer the hub reads: a [`FilePut`], or an error.
const MAX_ANSWER: usize = 64 * 1024;

/// How long an upload may take, from reaching the registry to its answer.
#[derive(Clone, Copy, Debug)]
struct Limits {
    /// To reach the registry.
    connect: Duration,
    /// Without a byte taken, before all were.
    stall: Duration,
    /// For the answer, once the last byte is sent.
    answer: Duration,
    /// For all of it: the token's lifetime.
    total: Duration,
}

impl Limits {
    fn new(total: Duration) -> Self {
        Limits {
            connect: Duration::from_secs(30),
            stall: Duration::from_secs(120),
            answer: Duration::from_secs(600),
            total,
        }
    }
}

/// Where the ISO 9660 primary volume descriptor starts, and how much of a medium's start
/// is kept to read it.
const PVD: usize = 0x8000;
pub(crate) const HEAD: usize = PVD + 2048;

/// The registry an upload goes to, and the token it is written with.
pub struct Target {
    pub registry: String,
    /// The repository path the media go under, if any.
    pub under: Option<String>,
    url: String,
    ca_pem: Option<String>,
    token: String,
    limits: Limits,
}

/// What an upload asks besides the bytes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Request {
    /// The registry to upload to; the one the fleet-wide `registry` setting names, or the
    /// only one that can take it, when `None`.
    #[serde(default)]
    pub registry: Option<String>,
    /// The repository path its `files/` are under: what nodes' `[build] cache_registry` names
    /// past the registry's host, if anything.
    #[serde(default)]
    pub under: Option<String>,
    /// The name it is uploaded under.
    pub name: String,
    /// Whether to approve it for jobs fleet-wide.
    pub approve: bool,
    /// What is said of it.
    #[serde(default)]
    pub edit: MediumEdit,
}

/// The file name a medium is tagged with: `name`'s last component, made a registry tag —
/// letters, digits, `.`, `_` and `-`, starting with a letter or digit, at most 128.
pub fn tag_name(name: &str) -> Result<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mapped: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let out: String = mapped
        .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .chars()
        .take(128)
        .collect();
    if out.is_empty() {
        bail!(
            "{:?} gives no file name to tag the medium with",
            vk_hub_proto::display_safe(name)
        );
    }
    Ok(out)
}

/// The volume label of the ISO 9660 image `head` starts, if it is one.
pub fn volume_label(head: &[u8]) -> Option<String> {
    let pvd = head.get(PVD..PVD + 72)?;
    if pvd[0] != 1 || &pvd[1..6] != b"CD001" {
        return None;
    }
    let label = String::from_utf8_lossy(&pvd[40..72]);
    let label = vk_hub_proto::display_safe(label.trim_end_matches([' ', '\0']));
    (!label.is_empty()).then_some(label)
}

/// What a volume label says of its medium: Microsoft's `<…>_<ARCH>…_<LANG>_<…>`, as
/// `SSS_X64FREE_EN-US_DV9`, gives the architecture and language of Windows media; virtio-win's
/// `virtio-win-<version>`, its product and version.
pub fn from_label(label: &str) -> MediumEdit {
    let mut out = MediumEdit::default();
    if let Some(version) = label.strip_prefix("virtio-win-") {
        out.kind = Some(MediumKind::Drivers);
        out.product = Some("virtio-win".into());
        out.version = Some(version.to_string());
        return out;
    }
    for part in label.split('_') {
        let upper = part.to_ascii_uppercase();
        if out.arch.is_none() {
            for (prefix, arch) in [
                ("X64", "x64"),
                ("ARM64", "arm64"),
                ("A64", "arm64"),
                ("X86", "x86"),
            ] {
                if upper.starts_with(prefix) {
                    out.arch = Some(arch.into());
                    break;
                }
            }
        }
        let lang = upper.split_once('-').is_some_and(|(l, r)| {
            l.len() == 2
                && (2..=4).contains(&r.len())
                && l.bytes().all(|b| b.is_ascii_alphabetic())
                && r.bytes().all(|b| b.is_ascii_alphabetic())
        });
        if lang && out.language.is_none() {
            out.language = Some(part.to_ascii_lowercase());
        }
    }
    if out.arch.is_some() && out.language.is_some() {
        out.kind = Some(MediumKind::Windows);
    }
    out
}

/// Fill fields absent from `edit` with `guess`.
pub(crate) fn guessed(edit: &MediumEdit, guess: MediumEdit) -> MediumEdit {
    MediumEdit {
        kind: edit.kind.or(guess.kind),
        product: edit.product.clone().or(guess.product),
        version: edit.version.clone().or(guess.version),
        language: edit.language.clone().or(guess.language),
        arch: edit.arch.clone().or(guess.arch),
        ..edit.clone()
    }
}

/// The manifest annotations a medium is stored with: what is said of it when it is uploaded.
pub fn annotations(info: &MediumInfo) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |key: &str, value: &str| {
        if !value.is_empty() {
            out.insert(key.to_string(), value.to_string());
        }
    };
    put("org.virtkit.media.kind", info.kind.name());
    put("org.virtkit.media.product", &info.product);
    put("org.virtkit.media.edition", &info.edition);
    put("org.virtkit.media.version", &info.version);
    put("org.virtkit.media.build", &info.build);
    put("org.virtkit.media.language", &info.language);
    put("org.virtkit.media.arch", &info.arch);
    put("org.virtkit.media.license", info.license.name());
    put("org.virtkit.media.obtained", &info.obtained);
    put("org.virtkit.media.expires", &info.expires);
    if let Some(source) = info.sources.first() {
        put("org.opencontainers.image.source", source);
    }
    out
}

/// The registry `asked`, or by default the one the fleet-wide `registry` setting names, or
/// the only registry: checked to take a medium of `size` bytes now, with a token minted for
/// it as `actor`.
pub fn target(
    hub: &Hub,
    actor: &str,
    asked: Option<&str>,
    under: Option<&str>,
    size: u64,
) -> Result<Target> {
    let under = under.map(|u| u.trim_matches('/')).filter(|u| !u.is_empty());
    if let Some(u) = under
        && !vk_hub_proto::token::servable_prefix(&format!("{u}/files/{DIR}"))
    {
        bail!(
            "{:?} is not a repository path, such as build-cache",
            vk_hub_proto::display_safe(u)
        );
    }
    let id = match asked {
        Some(id) => id.to_string(),
        None => default_registry(hub)?,
    };
    let Some(row) = hub.db.registry(&id)? else {
        bail!("there is no registry {id}");
    };
    if hub.reach(&id) != crate::server::Reach::Connected {
        bail!("registry {id} is not connected to the hub");
    }
    let inventory = row.inventory.as_ref();
    if !inventory.is_some_and(|i| i.files_put) {
        bail!("registry {id} does not take uploads from the hub: update it");
    }
    let Some(url) = row.url.clone() else {
        bail!(
            "registry {id} has no URL bound; bind one first (vk-hub registries set-url {id} \
             <url> [--ca <file>])"
        );
    };
    if !https_or_loopback(&url) {
        bail!(
            "registry {id} is bound to {url}: the hub sends its upload token over https only, \
             or plain http on loopback; bind an https URL"
        );
    }
    if let Some(free) = row.heartbeat.as_ref().map(|h| h.store_free_bytes)
        && size.saturating_add(HEADROOM) > free
    {
        bail!(
            "registry {id} has {free} bytes free, short of the {size} to upload and 1 GiB to spare"
        );
    }
    let ttl = TOKEN_TTL.min(hub.token_keys.max_token);
    let token = mint(hub, actor, &id, under, ttl)?;
    Ok(Target {
        registry: id,
        under: under.map(str::to_string),
        url,
        ca_pem: row.ca_pem,
        token,
        limits: Limits::new(ttl),
    })
}

/// The token an upload to registry `id` is written with, minted as `actor` for `ttl`: write
/// on the prefixes of the two repositories a medium is tagged in, `[<under>/]files/sha256`
/// and `[<under>/]files/win-media` (without `under`, `sha256` and `win-media`, which reach
/// `files/` through their own prefix).
fn mint(hub: &Hub, actor: &str, id: &str, under: Option<&str>, ttl: Duration) -> Result<String> {
    let grants = ["sha256", DIR]
        .map(|dir| Grant {
            prefix: match under {
                Some(u) => format!("{u}/files/{dir}"),
                None => dir.to_string(),
            },
            write: true,
            ..Grant::default()
        })
        .to_vec();
    crate::tokens::mint_for(hub, actor, SUBJECT, id, grants, None, ttl)
}

/// Whether a bound registry URL keeps a bearer token off the wire: `https`, or `http` to a
/// loopback host.
fn https_or_loopback(url: &str) -> bool {
    let Some(authority) = url.strip_prefix("http://") else {
        return url.starts_with("https://");
    };
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The registry an upload goes to unless one is named.
fn default_registry(hub: &Hub) -> Result<String> {
    if let Some(id) = named_registry(hub)? {
        return Ok(id);
    }
    let able = able_registries(hub)?;
    match &able[..] {
        [(id, _)] => Ok(id.clone()),
        [] => bail!(
            "no registry can take the upload now: none is connected, has a URL bound and \
             takes hub tokens and uploads"
        ),
        _ => bail!(
            "name the registry to upload to: {}",
            able.iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Registries by ID, with their hostname.
pub type Registries = Vec<(String, String)>;

/// The registries that can take an upload now, and the one the fleet-wide `registry` setting
/// names, if any.
pub fn choices(hub: &Hub) -> Result<(Registries, Option<String>)> {
    Ok((able_registries(hub)?, named_registry(hub)?))
}

/// The registry the fleet-wide `registry` setting names, if any.
fn named_registry(hub: &Hub) -> Result<Option<String>> {
    let fleet = hub.db.settings_layers()?.fleet;
    Ok(fleet
        .get("registry")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

/// The registries that can take an upload now.
fn able_registries(hub: &Hub) -> Result<Registries> {
    Ok(hub
        .db
        .registries()?
        .into_iter()
        .filter(|(id, row)| {
            row.url.is_some()
                && row
                    .inventory
                    .as_ref()
                    .is_some_and(|i| i.files_put && i.tokens)
                && hub.reach(id) == Reach::Connected
        })
        .map(|(id, row)| (id, row.hostname))
        .collect())
}

/// What passed through an upload, as the hub saw it.
#[derive(Default)]
struct Tap {
    hasher: Sha256,
    bytes: u64,
    head: Vec<u8>,
}

/// What the hub saw of the bytes it sent.
#[derive(Debug)]
pub struct Sent {
    pub put: FilePut,
    pub volume_label: Option<String>,
}

/// Stream `body`, `size` bytes, to `target` as `name`, with `annotations`: what the
/// registry stored, once it answered with the sha256 and size the hub saw pass.
pub async fn send<S>(
    target: &Target,
    name: &str,
    size: u64,
    annotations: &BTreeMap<String, String>,
    body: S,
) -> Result<Sent>
where
    S: Stream<Item = Result<Bytes>> + Send + 'static,
{
    if size == 0 {
        // Nothing would read the source to its end: an empty one could still be growing.
        bail!("an empty file is no medium");
    }
    let limits = target.limits;
    tokio::time::timeout(
        limits.total,
        send_within(target, name, size, annotations, body, limits),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "uploading to registry {}: not done within {}s",
            target.registry,
            limits.total.as_secs()
        )
    })?
}

async fn send_within<S>(
    target: &Target,
    name: &str,
    size: u64,
    annotations: &BTreeMap<String, String>,
    body: S,
    limits: Limits,
) -> Result<Sent>
where
    S: Stream<Item = Result<Bytes>> + Send + 'static,
{
    let tls = client_tls(target.ca_pem.as_deref())?;
    let dialed = tokio::time::timeout(limits.connect, vk_peer::session::dial(&target.url, &tls))
        .await
        .map_err(|_| anyhow!("registry {} was not reached in time", target.registry))?
        .with_context(|| format!("reaching registry {}", target.registry))?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(dialed.io))
            .await
            .context("opening the upload")?;
    let driver = tokio::spawn(conn);
    let _driver = AbortOnDrop(driver);
    let tap = Arc::new(Mutex::new(Tap::default()));
    let body = tapped(body, tap.clone(), size);
    let mut path = format!("{FILES_PATH}{DIR}/{name}");
    if let Some(u) = &target.under {
        path.push_str(&format!("?under={u}"));
    }
    let mut request = hyper::Request::put(path)
        .header(hyper::header::HOST, &dialed.authority)
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", target.token),
        )
        .header(hyper::header::CONTENT_LENGTH, size)
        .header(FILE_RETENTION_HEADER, RETENTION_KEEP);
    if !annotations.is_empty() {
        let json = serde_json::to_vec(annotations)?;
        request = request.header(
            FILE_ANNOTATIONS_HEADER,
            vk_hub_proto::token::to_base64url(&json),
        );
    }
    let request = request
        .body(http_body_util::StreamBody::new(body))
        .context("building the upload")?;
    let answer = sender.send_request(request);
    let resp = tokio::select! {
        resp = answer => resp.with_context(|| format!("uploading to registry {}", target.registry))?,
        why = stalled(&tap, size, limits) => bail!("uploading to registry {}: {why}", target.registry),
    };
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(hyper::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let said = tokio::time::timeout(
        limits.answer,
        http_body_util::Limited::new(resp.into_body(), MAX_ANSWER).collect(),
    )
    .await
    .map_err(|_| anyhow!("registry {} did not answer in time", target.registry))?
    .map_err(|e| anyhow!("reading registry {}'s answer: {e}", target.registry))?
    .to_bytes();
    if status != hyper::StatusCode::CREATED {
        return Err(refusal(&target.registry, status, retry_after, &said).into());
    }
    let put: FilePut =
        serde_json::from_slice(&said).context("reading the registry's answer to the upload")?;
    let tap = std::mem::take(&mut *tap.lock().unwrap_or_else(|e| e.into_inner()));
    let sha256 = vk_hub_proto::to_hex(&tap.hasher.finalize());
    if put.sha256 != sha256 || put.size != tap.bytes || tap.bytes != size {
        bail!(
            "registry {} stored {} bytes hashing to {}, not the {} hashing to {sha256} the hub sent",
            target.registry,
            put.size,
            vk_hub_proto::display_safe(&put.sha256),
            tap.bytes
        );
    }
    if !put
        .manifest
        .strip_prefix("sha256:")
        .is_some_and(vk_hub_proto::valid_sha256)
    {
        bail!(
            "registry {} named no manifest for the upload",
            target.registry
        );
    }
    Ok(Sent {
        put,
        volume_label: volume_label(&tap.head),
    })
}

/// `body`, hashed into `tap` as it passes, ending in an error rather than giving the registry
/// other than exactly `size` bytes: the source must end once `size` bytes came, checked
/// before the last of them is sent, since the registry stops reading there.
fn tapped<S>(
    body: S,
    tap: Arc<Mutex<Tap>>,
    size: u64,
) -> impl Stream<Item = Result<hyper::body::Frame<Bytes>>> + Send + 'static
where
    S: Stream<Item = Result<Bytes>> + Send + 'static,
{
    let body = Box::pin(body);
    futures::stream::try_unfold(
        (body, tap, false),
        move |(mut body, tap, ended)| async move {
            if ended {
                return Ok(None);
            }
            let chunk = loop {
                match body.next().await {
                    None => return Ok(None),
                    Some(chunk) => {
                        let chunk = chunk?;
                        if !chunk.is_empty() {
                            break chunk;
                        }
                    }
                }
            };
            let bytes = {
                let mut t = tap.lock().unwrap_or_else(|e| e.into_inner());
                t.hasher.update(&chunk);
                t.bytes = t.bytes.saturating_add(chunk.len() as u64);
                if t.head.len() < HEAD {
                    let n = HEAD.saturating_sub(t.head.len()).min(chunk.len());
                    t.head.extend_from_slice(chunk.get(..n).unwrap_or_default());
                }
                t.bytes
            };
            if bytes > size {
                bail!("more than the {size} bytes declared arrived");
            }
            let ended = bytes == size;
            if ended {
                while let Some(more) = body.next().await {
                    if !more?.is_empty() {
                        bail!("more than the {size} bytes declared arrived");
                    }
                }
            }
            Ok(Some((hyper::body::Frame::data(chunk), (body, tap, ended))))
        },
    )
}

/// The registry's refusal of an upload: its status, what it said, and when to try again if it
/// said.
#[derive(Debug)]
pub struct Refused {
    pub status: hyper::StatusCode,
    pub retry_after: Option<u64>,
    text: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Refused {}

/// Registry `id`'s refusal of an upload with `status`, from the body it `said`.
pub(crate) fn refusal(
    id: &str,
    status: hyper::StatusCode,
    retry_after: Option<u64>,
    said: &[u8],
) -> Refused {
    let message = serde_json::from_slice::<serde_json::Value>(said)
        .ok()
        .and_then(|v| v["errors"][0]["message"].as_str().map(str::to_string));
    let mut text = format!("registry {id} refused the upload (HTTP {status})");
    if let Some(m) = message {
        text.push_str(&format!(": {}", vk_hub_proto::display_safe(&m)));
    }
    if let Some(secs) = retry_after {
        text.push_str(&format!("; try again in {secs}s"));
    }
    Refused {
        status,
        retry_after,
        text,
    }
}

/// Once the upload stalls: no byte taken for `limits.stall` while some are still to send, or
/// no answer `limits.answer` after the last one was. Why.
async fn stalled(tap: &Mutex<Tap>, size: u64, limits: Limits) -> String {
    let bytes = || tap.lock().unwrap_or_else(|e| e.into_inner()).bytes;
    let every = (limits.stall / 4).min(Duration::from_secs(5));
    let (mut seen, mut since) = (bytes(), tokio::time::Instant::now());
    loop {
        tokio::time::sleep(every).await;
        let now = bytes();
        if now != seen {
            (seen, since) = (now, tokio::time::Instant::now());
        } else if now < size && since.elapsed() >= limits.stall {
            return format!(
                "no byte went for {}s, at {now} of {size}",
                limits.stall.as_secs()
            );
        } else if now >= size && since.elapsed() >= limits.answer {
            return format!(
                "the registry did not answer within {}s of the last byte",
                limits.answer.as_secs()
            );
        }
    }
}

/// Record the medium `sent` to `target` as `name`, as `actor` uploaded it with `request`,
/// and send the nodes its approval reaches their settings.
pub fn record(
    hub: &Hub,
    actor: &str,
    target: &Target,
    name: &str,
    sent: &Sent,
    request: &Request,
    now: u64,
) -> Result<MediumAdded> {
    let edit = match &sent.volume_label {
        Some(label) => guessed(&request.edit, from_label(label)),
        None => request.edit.clone(),
    };
    let (info, _) = edit.apply(&MediumInfo::default())?;
    let row = MediumRow {
        file_name: name.to_string(),
        size: sent.put.size,
        volume_label: sent.volume_label.clone(),
        added_at: now,
        added_by: actor.to_string(),
        edited_at: None,
        edited_by: None,
        info,
        locations: Vec::new(),
    };
    let location = Location {
        registry: target.registry.clone(),
        under: target.under.clone(),
        name: name.to_string(),
        manifest: sent.put.manifest.clone(),
        at: now,
        by: actor.to_string(),
    };
    let added = hub
        .db
        .add_medium(&sent.put.sha256, row, location, request.approve)
        .with_context(|| {
            format!(
                "{}, but the hub could not record it; upload it again once that is fixed",
                held(target, name, &sent.put.sha256)
            )
        })?;
    eprintln!(
        "vk-hub: {actor} uploaded {} medium {} ({name}) to registry {}",
        if added.known { "the known" } else { "new" },
        sent.put.sha256,
        target.registry
    );
    crate::settings::sent(hub, &added.steered);
    hub.touch();
    Ok(added)
}

/// Where `target` holds medium `sha256`, stored as `name`.
pub fn held(target: &Target, name: &str, sha256: &str) -> String {
    let under = target
        .under
        .as_ref()
        .map_or(String::new(), |u| format!("{u}/"));
    format!(
        "registry {} holds medium {sha256} as {under}files/{DIR}:{name}",
        target.registry
    )
}

/// One upload at a time: refused while another runs.
pub fn slot(hub: &Hub) -> Result<tokio::sync::OwnedSemaphorePermit> {
    hub.media_uploads
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow!("another medium is being uploaded; wait for it to end"))
}

/// `vk-hub media add`: upload the file at `path`, read by the hub, as `actor` asked with
/// `request`.
pub async fn add_path(
    hub: &Arc<Hub>,
    actor: &str,
    path: &std::path::Path,
    mut request: Request,
) -> Result<MediumAdded> {
    let _slot = slot(hub)?;
    // Refused now rather than once the registry holds it; the record checks again.
    hub.db.media_room(request.approve)?;
    // Without blocking, so a FIFO is refused rather than waited on; read through this one
    // descriptor, so what is uploaded is what was checked.
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a file", path.display());
    }
    let size = meta.len();
    let mut file = tokio::fs::File::from_std(file);
    // Read ahead for what the label tells, so the annotations carry it.
    let mut head = vec![0u8; HEAD.min(usize::try_from(size).unwrap_or(HEAD))];
    {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        file.read_exact(&mut head).await?;
        file.seek(std::io::SeekFrom::Start(0)).await?;
    }
    if let Some(label) = volume_label(&head) {
        request.edit = guessed(&request.edit, from_label(&label));
    }
    let (info, _) = request.edit.apply(&MediumInfo::default())?;
    // A tag is ASCII: a file name that is not UTF-8 maps to one as any other character
    // outside a tag's does.
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let name = tag_name(if request.name.is_empty() {
        &file_name
    } else {
        &request.name
    })?;
    let (hub2, actor2) = (hub.clone(), actor.to_string());
    let (asked, under) = (request.registry.clone(), request.under.clone());
    let target = tokio::task::spawn_blocking(move || {
        target(&hub2, &actor2, asked.as_deref(), under.as_deref(), size)
    })
    .await
    .context("choosing the registry")??;
    let body = futures::stream::try_unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 1 << 20];
        let n = file.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok::<_, anyhow::Error>(Some((Bytes::from(buf), file)))
    });
    let sent = send(&target, &name, size, &annotations(&info), body).await?;
    let (hub2, actor2) = (hub.clone(), actor.to_string());
    tokio::task::spawn_blocking(move || {
        record(
            &hub2,
            &actor2,
            &target,
            &name,
            &sent,
            &request,
            crate::now_secs(),
        )
    })
    .await
    .context("recording the medium")?
}

/// Change what is said of medium `sha256` with `edit`, as `actor`, if it is still at revision
/// `seen` when one is given.
pub fn edit(
    hub: &Hub,
    actor: &str,
    sha256: &str,
    edit: &MediumEdit,
    seen: Option<&str>,
) -> Result<Medium> {
    let medium = hub
        .db
        .edit_medium(sha256, edit, seen, actor, crate::now_secs())?
        .with_context(|| format!("there is no medium {sha256}"))?;
    hub.touch();
    Ok(medium)
}

/// Approve medium `sha256` for jobs fleet-wide, or withdraw it, as `actor`: whether it
/// changed.
pub fn approve(hub: &Hub, actor: &str, sha256: &str, approve: bool) -> Result<bool> {
    let (changed, steered) = hub
        .db
        .approve_medium(sha256, approve, actor, crate::now_secs())?;
    if changed {
        eprintln!(
            "vk-hub: {actor} {} medium {sha256}",
            if approve { "approved" } else { "withdrew" }
        );
        crate::settings::sent(hub, &steered);
        hub.touch();
    }
    Ok(changed)
}

/// Forget medium `sha256` and withdraw its approval, as `actor`, if it is still at revision
/// `seen` when one is given; the registries keep their copies. The medium, `None` when another
/// removal took it first.
pub fn remove(hub: &Hub, actor: &str, sha256: &str, seen: Option<&str>) -> Result<Option<Medium>> {
    let Some((medium, steered)) = hub
        .db
        .remove_medium(sha256, seen, actor, crate::now_secs())?
    else {
        return Ok(None);
    };
    eprintln!("vk-hub: {actor} removed medium {sha256}");
    crate::settings::sent(hub, &steered);
    hub.touch();
    Ok(Some(medium))
}

/// The client TLS for a registry: its bound CA alone when it has one, the platform's roots
/// otherwise.
fn client_tls(ca_pem: Option<&str>) -> Result<Arc<rustls::ClientConfig>> {
    let Some(pem) = ca_pem else {
        return vk_peer::net::client_tls(None);
    };
    let roots =
        vk_peer::net::roots_from_pem(pem.as_bytes(), std::path::Path::new("the registry's CA"))?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("building the TLS client config")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How a fake registry answers a file put.
    #[derive(Clone, Copy)]
    enum Answer {
        /// With what arrived.
        Honest,
        /// With what arrived, but this sha256.
        Lie(&'static str),
        /// With this status at once, reading nothing, as when busy (503) or short of room
        /// (507).
        Refuse(u16),
        /// With 408 once this many bytes arrived, as when the body idles.
        Cut(usize),
        /// Never: reads nothing, holds the connection.
        Hold,
        /// Never: reads everything, then holds the connection.
        Mute,
        /// 201 with this many bytes of answer.
        Huge(usize),
        /// 201 with an answer that is not a `FilePut`.
        Junk,
    }

    /// A registry's file put, by hand.
    async fn fake_registry(answer: Answer) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| async move {
                        assert!(req.uri().path().starts_with("/files/win-media/"));
                        assert!(
                            req.headers()["authorization"]
                                .to_str()
                                .unwrap()
                                .starts_with("Bearer ")
                        );
                        assert_eq!(req.headers()[FILE_RETENTION_HEADER], RETENTION_KEEP);
                        let reply = |status: u16, body: Vec<u8>| {
                            hyper::Response::builder()
                                .status(status)
                                .header(hyper::header::RETRY_AFTER, "60")
                                .body(http_body_util::Full::new(Bytes::from(body)))
                                .unwrap()
                        };
                        let error = |message: &str| {
                            serde_json::to_vec(&serde_json::json!({
                                "errors": [{"code": "X", "message": message}]
                            }))
                            .unwrap()
                        };
                        let mut body = req.into_body();
                        let mut got = Vec::new();
                        match answer {
                            Answer::Refuse(status) => {
                                return Ok(reply(status, error("not now")));
                            }
                            Answer::Hold => std::future::pending::<()>().await,
                            Answer::Cut(n) => {
                                while got.len() < n {
                                    let Some(frame) = body.frame().await else {
                                        break;
                                    };
                                    if let Ok(data) = frame?.into_data() {
                                        got.extend_from_slice(&data);
                                    }
                                }
                                return Ok(reply(408, error("the body idled")));
                            }
                            _ => got = body.collect().await?.to_bytes().to_vec(),
                        }
                        let sha = vk_hub_proto::to_hex(&Sha256::digest(&got));
                        let put = FilePut {
                            sha256: match answer {
                                Answer::Lie(sha) => sha.to_string(),
                                _ => sha,
                            },
                            size: got.len() as u64,
                            manifest: format!("sha256:{}", "0".repeat(64)),
                        };
                        Ok::<_, hyper::Error>(match answer {
                            Answer::Mute => std::future::pending().await,
                            Answer::Huge(n) => reply(201, vec![b' '; n]),
                            Answer::Junk => reply(201, b"{}".to_vec()),
                            _ => reply(201, serde_json::to_vec(&put).unwrap()),
                        })
                    },
                );
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service),
                );
            }
        });
        format!("http://{addr}")
    }

    fn fake_target(url: String) -> Target {
        Target {
            registry: "r".into(),
            under: None,
            url,
            ca_pem: None,
            token: "vkt_x".into(),
            limits: Limits {
                connect: Duration::from_secs(5),
                stall: Duration::from_secs(1),
                answer: Duration::from_secs(1),
                total: Duration::from_secs(60),
            },
        }
    }

    fn chunks(parts: Vec<Result<Bytes>>) -> impl Stream<Item = Result<Bytes>> + Send + 'static {
        futures::stream::iter(parts)
    }

    /// An ISO 9660 image's start, labelled virtio-win, and some more.
    fn iso() -> Vec<u8> {
        let mut iso = vec![0u8; HEAD + 1000];
        iso[PVD] = 1;
        iso[PVD + 1..PVD + 6].copy_from_slice(b"CD001");
        iso[PVD + 40..PVD + 72].copy_from_slice(b"virtio-win-0.1.302              ");
        iso
    }

    fn split(iso: &[u8]) -> Vec<Result<Bytes>> {
        iso.chunks(4096)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect()
    }

    /// `n` MiB, sent a MiB at a time.
    fn mib(n: usize) -> (u64, impl Stream<Item = Result<Bytes>> + Send + 'static) {
        let one = Bytes::from(vec![7u8; 1 << 20]);
        (
            (n << 20) as u64,
            futures::stream::iter(std::iter::repeat_n(one, n).map(Ok)),
        )
    }

    async fn send_err(
        target: &Target,
        size: u64,
        body: impl Stream<Item = Result<Bytes>> + Send + 'static,
    ) -> String {
        let err = send(target, "v.iso", size, &BTreeMap::new(), body)
            .await
            .unwrap_err();
        format!("{err:#}")
    }

    #[tokio::test]
    async fn an_upload_is_recorded_only_as_the_hub_saw_it() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let iso = iso();
        let size = iso.len() as u64;
        let honest = fake_target(fake_registry(Answer::Honest).await);
        let sent = send(
            &honest,
            "v.iso",
            size,
            &BTreeMap::new(),
            chunks(split(&iso)),
        )
        .await
        .unwrap();
        assert_eq!(sent.put.sha256, vk_hub_proto::to_hex(&Sha256::digest(&iso)));
        assert_eq!(sent.volume_label.as_deref(), Some("virtio-win-0.1.302"));

        // A registry claiming other bytes is not believed.
        let liar = fake_target(fake_registry(Answer::Lie("ab")).await);
        let err = send_err(&liar, size, chunks(split(&iso))).await;
        assert!(err.contains("not the"), "{err}");

        // Bytes that stop coming end the upload.
        let mut cut = split(&iso);
        cut.truncate(2);
        cut.push(Err(anyhow!("the browser went away")));
        send_err(&honest, size, chunks(cut)).await;
        // As do more than were declared, within a chunk or past the last one declared.
        send_err(&honest, size - 1, chunks(split(&iso))).await;
        let mut more = split(&iso);
        more.push(Ok(Bytes::from_static(b"x")));
        let err = send_err(&honest, size, chunks(more)).await;
        assert!(err.contains("more than"), "{err}");
        let mut broken = split(&iso);
        broken.push(Err(anyhow!("read error past the end")));
        let err = send_err(&honest, size, chunks(broken)).await;
        assert!(err.contains("read error"), "{err}");
        // And fewer.
        let mut fewer = split(&iso);
        fewer.pop();
        send_err(&honest, size, chunks(fewer)).await;
        // And none, whatever follows.
        let err = send_err(&honest, 0, chunks(vec![Ok(Bytes::from_static(b"x"))])).await;
        assert!(err.contains("empty file"), "{err}");
    }

    #[tokio::test]
    async fn a_refused_upload_says_why() {
        for (status, want) in [
            (
                503,
                "HTTP 503 Service Unavailable): not now; try again in 60s",
            ),
            (507, "HTTP 507 Insufficient Storage): not now"),
        ] {
            let busy = fake_target(fake_registry(Answer::Refuse(status)).await);
            let (size, body) = mib(32);
            let err = send_err(&busy, size, body).await;
            assert!(err.contains(want), "{err}");
        }
        let idle = fake_target(fake_registry(Answer::Cut(1 << 20)).await);
        let (size, body) = mib(32);
        let err = send_err(&idle, size, body).await;
        assert!(err.contains("HTTP 408"), "{err}");

        let huge = fake_target(fake_registry(Answer::Huge(MAX_ANSWER + 1)).await);
        let err = send_err(&huge, 3, chunks(vec![Ok(Bytes::from_static(b"abc"))])).await;
        assert!(err.contains("reading registry r's answer"), "{err}");
        let junk = fake_target(fake_registry(Answer::Junk).await);
        let err = send_err(&junk, 3, chunks(vec![Ok(Bytes::from_static(b"abc"))])).await;
        assert!(err.contains("answer to the upload"), "{err}");
    }

    #[tokio::test]
    async fn a_stalled_upload_is_abandoned() {
        // The source stops giving bytes.
        let honest = fake_target(fake_registry(Answer::Honest).await);
        let first = futures::stream::iter([Ok(Bytes::from_static(b"abc"))]);
        let err = send_err(&honest, 10, first.chain(futures::stream::pending())).await;
        assert!(err.contains("no byte went"), "{err}");
        // The registry stops taking them.
        let hold = fake_target(fake_registry(Answer::Hold).await);
        let (size, body) = mib(64);
        let err = send_err(&hold, size, body).await;
        assert!(err.contains("no byte went"), "{err}");
        // The registry takes them all and never answers.
        let mute = fake_target(fake_registry(Answer::Mute).await);
        let err = send_err(&mute, 3, chunks(vec![Ok(Bytes::from_static(b"abc"))])).await;
        assert!(err.contains("did not answer"), "{err}");
        // Bytes trickling in forever still end.
        let mut slow = fake_target(fake_registry(Answer::Honest).await);
        slow.limits.total = Duration::from_secs(2);
        let trickle = futures::stream::unfold((), |()| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Some((Ok(Bytes::from_static(b"x")), ()))
        });
        let err = send_err(&slow, 1 << 20, trickle).await;
        assert!(err.contains("not done within 2s"), "{err}");
    }

    #[test]
    fn only_https_or_loopback_gets_the_token() {
        for ok in [
            "https://reg.example.com",
            "http://127.0.0.1:5000",
            "http://[::1]:5000",
            "http://localhost",
        ] {
            assert!(https_or_loopback(ok), "{ok}");
        }
        for bad in [
            "http://reg.example.com",
            "http://10.0.0.1:5000",
            "http://[fe80::1]",
        ] {
            assert!(!https_or_loopback(bad), "{bad}");
        }
    }

    #[test]
    fn the_hub_mints_itself_a_token_for_the_two_repositories() {
        let dir = std::env::temp_dir().join(format!("vk-hub-media-mint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hub = Hub::new(
            std::sync::Arc::new(crate::store::Db::open_memory().unwrap()),
            None,
        )
        .with_token_keys(dir.join("token-keys"), crate::tokens::DEFAULT_MAX_JOB_TOKEN);
        let id = crate::tests::tokens::token_registry(&hub, "https://reg.example.com", "aa");
        let ttl = Duration::from_secs(3600);
        let token = mint(&hub, "uid 0", &id, Some("build-cache"), ttl).unwrap();
        let keys = hub
            .db
            .registry(&id)
            .unwrap()
            .unwrap()
            .desired
            .unwrap()
            .token_keys
            .unwrap();
        let claims = vk_peer::token::verify(&token, &keys, &id, crate::now_secs()).unwrap();
        assert_eq!(claims.sub, SUBJECT);
        assert_eq!(claims.aud, id);
        assert_eq!(claims.exp - claims.iat, ttl.as_secs());
        let prefixes: Vec<_> = claims.grants.iter().map(|g| g.prefix.as_str()).collect();
        assert_eq!(
            prefixes,
            ["build-cache/files/sha256", "build-cache/files/win-media"]
        );
        assert!(claims.grants.iter().all(|g| g.write && !g.read && !g.lock));
        // Past the hub's ceiling, or for a registry that does not take tokens, none.
        assert!(mint(&hub, "uid 0", &id, None, Duration::from_secs(u64::MAX / 2)).is_err());
        assert!(mint(&hub, "uid 0", "nope", None, ttl).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stored_medium_the_hub_cannot_record_says_where_it_is() {
        let hub = Hub::new(
            std::sync::Arc::new(crate::store::Db::open_memory().unwrap()),
            None,
        );
        let full: Vec<String> = (0..vk_hub_proto::settings::MAX_DIGESTS)
            .map(|i| format!("{i:064x}"))
            .collect();
        hub.db
            .set_setting(
                None,
                "executor.windows_media",
                Some(serde_json::Value::from(full)),
                "op",
                1,
            )
            .unwrap();
        assert!(hub.db.media_room(true).is_err());
        hub.db.media_room(false).unwrap();
        let target = Target {
            under: Some("build-cache".into()),
            ..fake_target(String::new())
        };
        let sha = "a".repeat(64);
        let sent = Sent {
            put: FilePut {
                sha256: sha.clone(),
                size: 3,
                manifest: format!("sha256:{}", "0".repeat(64)),
            },
            volume_label: None,
        };
        let request = Request {
            name: "v.iso".into(),
            approve: true,
            ..Request::default()
        };
        let err = record(&hub, "uid 0", &target, "v.iso", &sent, &request, 2).unwrap_err();
        let err = format!("{err:#}");
        assert!(
            err.contains(&format!(
                "registry r holds medium {sha} as build-cache/files/win-media:v.iso"
            )),
            "{err}"
        );
        assert!(hub.db.medium(&sha).unwrap().is_none());
    }

    #[test]
    fn an_upload_needs_a_registry_that_can_take_it() {
        let hub = Hub::new(
            std::sync::Arc::new(crate::store::Db::open_memory().unwrap()),
            None,
        );
        let err = target(&hub, "uid 0", None, None, 1).err().unwrap();
        assert!(
            format!("{err:#}").contains("no registry can take"),
            "{err:#}"
        );
        let err = target(&hub, "uid 0", None, Some("Bad Path"), 1)
            .err()
            .unwrap();
        assert!(
            format!("{err:#}").contains("not a repository path"),
            "{err:#}"
        );
        let err = target(&hub, "uid 0", Some("nope"), Some("/build-cache/"), 1)
            .err()
            .unwrap();
        assert!(
            format!("{err:#}").contains("there is no registry"),
            "{err:#}"
        );
    }

    #[test]
    fn a_label_says_what_it_can() {
        let ws = from_label("SSS_X64FREE_EN-US_DV9");
        assert_eq!(ws.kind, Some(MediumKind::Windows));
        assert_eq!(ws.arch.as_deref(), Some("x64"));
        assert_eq!(ws.language.as_deref(), Some("en-us"));
        let virtio = from_label("virtio-win-0.1.302");
        assert_eq!(virtio.kind, Some(MediumKind::Drivers));
        assert_eq!(virtio.version.as_deref(), Some("0.1.302"));
        assert_eq!(from_label("CDROM"), MediumEdit::default());
        // What the operator said wins.
        let said = MediumEdit {
            arch: Some("arm64".into()),
            ..MediumEdit::default()
        };
        assert_eq!(guessed(&said, ws).arch.as_deref(), Some("arm64"));
    }

    #[test]
    fn a_volume_label_is_read_from_the_primary_descriptor() {
        let mut iso = vec![0u8; HEAD];
        iso[PVD] = 1;
        iso[PVD + 1..PVD + 6].copy_from_slice(b"CD001");
        iso[PVD + 40..PVD + 72].copy_from_slice(b"SSS_X64FREE_EN-US_DV9           ");
        assert_eq!(volume_label(&iso).as_deref(), Some("SSS_X64FREE_EN-US_DV9"));
        assert_eq!(volume_label(&iso[..PVD]), None);
        iso[PVD + 1] = b'X';
        assert_eq!(volume_label(&iso), None);
    }

    #[test]
    fn a_file_name_becomes_a_tag() {
        assert_eq!(
            tag_name("/data/ws2025-eval-en-us.iso").unwrap(),
            "ws2025-eval-en-us.iso"
        );
        assert_eq!(
            tag_name("C:\\isos\\my disk (1).iso").unwrap(),
            "my-disk--1-.iso"
        );
        assert_eq!(tag_name(".hidden").unwrap(), "hidden");
        assert!(tag_name("///").is_err());
        assert_eq!(tag_name(&"a".repeat(300)).unwrap().len(), 128);
    }
}
