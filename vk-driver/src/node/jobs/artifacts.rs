//! A placed job's artifacts, between the node and GitLab with the job's tokens, as
//! gitlab-runner's `artifacts-downloader` and `artifacts-uploader` move them: dependencies'
//! archives downloaded and unpacked into the project dir, the job's own archived in the guest
//! and uploaded. See `docs/gitlab-dispatch.md`, "Artifacts and caches".
//!
//! Follows gitlab-runner v19.5: `shells/abstract.go` (`writeUploadArtifacts`,
//! `writeUploadArtifact`, `downloadAllArtifacts`) for what runs,
//! `commands/helpers/artifacts_uploader.go` and `artifacts_downloader.go` for the retries and
//! the redirect handling, and `network/gitlab.go` (`UploadRawArtifacts`, `DownloadArtifacts`)
//! for the requests and the lines they log. gitlab-runner is MIT (see [`super::mask`] for the
//! notice).

mod zip;

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use vk_hub_proto::job::{ArtifactFormat, ArtifactOutcome, ArtifactSpec, Dependency, UploadState};

use super::StageCtx;
use super::guest::{self, Selection};
use super::transfer::{self, Capped, MAX_STAGED, create, too_large};

/// The upload tries gitlab-runner makes (`defaultTries`), and after a 503
/// (`serviceUnavailableTries`).
const UPLOAD_TRIES: u32 = 3;
const UNAVAILABLE_TRIES: u32 = 6;
/// The download tries `artifacts-downloader` makes (`Retry: 2` retries after the first).
const DOWNLOAD_TRIES: u32 = 3;
/// gitlab-runner's `DefaultArtifactUploadTimeout`.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(3600);
/// The longest `Retry-After` honoured.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// Redirects a download follows.
const MAX_REDIRECTS: usize = 10;
/// How much of an error answer is read for its message.
const MAX_ERROR_BODY: usize = 4096;
const CHUNK: usize = 256 * 1024;

/// Whether `download_artifacts` has anything to do: a dependency with an archive.
pub fn download_applies(ctx: &StageCtx<'_>) -> bool {
    ctx.job
        .dependencies
        .iter()
        .any(|d| d.artifacts_file.is_some())
}

/// Whether `upload_artifacts_on_success` (`succeeded`) or `_on_failure` has anything to do:
/// an artifact whose `when` applies and that selects something.
pub fn upload_applies(ctx: &StageCtx<'_>, succeeded: bool) -> bool {
    !ctx.job.server_url.is_empty()
        && ctx
            .job
            .artifacts
            .iter()
            .any(|a| a.when.applies(succeeded) && selects(a))
}

/// `writeUploadArtifact`: an artifact with no paths, excludes or `untracked` is not archived.
fn selects(a: &ArtifactSpec) -> bool {
    !a.paths.is_empty() || !a.exclude.is_empty() || a.untracked
}

/// `download_artifacts`, one attempt: every dependency's archive into the project dir.
pub async fn download(ctx: &StageCtx<'_>) -> Result<()> {
    let client = client(ctx)?;
    for dep in ctx
        .job
        .dependencies
        .iter()
        .filter(|d| d.artifacts_file.is_some())
    {
        ctx.trace.notice(&format!(
            "Downloading artifacts for {} ({})...",
            dep.name, dep.id
        ));
        download_one(ctx, &client, dep)
            .await
            .with_context(|| format!("downloading the artifacts of {} ({})", dep.name, dep.id))?;
    }
    Ok(())
}

async fn download_one(
    ctx: &StageCtx<'_>,
    client: &reqwest::Client,
    dep: &Dependency,
) -> Result<()> {
    let zip_path = ctx.scratch.join(format!("dependency-{}.zip", dep.id));
    let out = async {
        let mut tries = 0;
        loop {
            tries += 1;
            match fetch(ctx, client, dep, &zip_path).await {
                Ok(()) => break,
                Err(Fetch::Final(e)) => return Err(e),
                Err(Fetch::Retry(e)) if tries < DOWNLOAD_TRIES => {
                    ctx.trace.warning(&format!("{e:#} (will retry)"));
                    cancelable(ctx, tokio::time::sleep(Duration::from_secs(1))).await?;
                }
                Err(Fetch::Retry(e)) => return Err(e),
            }
        }
        // The zip is read from its end, so it is kept; the tar made of it streams to the guest.
        let zip_in = zip_path.clone();
        let (mut tar, unpacked) = transfer::from_blocking(move |out| unzip_to_tar(&zip_in, out));
        let extracted = cancelable(
            ctx,
            guest::extract(&ctx.addr, ctx.user.as_deref(), &ctx.project_dir, &mut tar),
        )
        .await?;
        transfer::drain(&mut tar, &extracted).await;
        drop(tar);
        let unpacked = transfer::joined(unpacked)
            .await
            .context("unpacking the artifacts");
        let (warnings, ()) = transfer::both(unpacked, extracted)?;
        for w in warnings {
            ctx.trace.warning(&w);
        }
        Ok(())
    }
    .await;
    remove(&zip_path);
    out
}

/// The archive at `zip` as a tar on `out`. Returns what it left out.
fn unzip_to_tar(zip: &Path, out: &mut dyn Write) -> Result<Vec<String>> {
    let mut input = File::open(zip).context("opening the downloaded artifacts")?;
    let mut magic = [0u8; 2];
    let n = input.read(&mut magic)?;
    if n < 2 || &magic != b"PK" {
        bail!(
            "the artifacts archive is not a zip; only zip archives can be downloaded on vk nodes"
        );
    }
    let mut warnings = Vec::new();
    zip::zip_to_tar(
        &mut input,
        std::io::BufWriter::with_capacity(CHUNK, out),
        &mut |w| warnings.push(w),
    )?;
    Ok(warnings)
}

/// Why a download failed: worth another try, or not.
enum Fetch {
    Retry(anyhow::Error),
    Final(anyhow::Error),
}

/// `GET /jobs/<id>/artifacts` into `dest`, following redirects and sending the dependency's
/// token to GitLab's own origin only.
async fn fetch(
    ctx: &StageCtx<'_>,
    client: &reqwest::Client,
    dep: &Dependency,
    dest: &Path,
) -> std::result::Result<(), Fetch> {
    let base = api_base(&ctx.job.server_url).map_err(Fetch::Final)?;
    let mut url = reqwest::Url::parse(&format!("{base}/jobs/{}/artifacts", dep.id))
        .map_err(|e| Fetch::Final(anyhow!("bad GitLab URL: {e}")))?;
    let home = origin(&url);
    let fields = format!("id={} token={}", dep.id, short_token(&dep.token));
    let what = "Downloading artifacts from coordinator...";
    let mut redirects = 0;
    let resp = loop {
        let mut req = client.get(url.clone());
        if home == origin(&url) {
            req = req.header("JOB-TOKEN", &dep.token);
        }
        let resp = cancelable(ctx, req.send())
            .await
            .map_err(Fetch::Final)?
            .map_err(|e| {
                ctx.trace.error(&format!("{what} error  {fields}"));
                Fetch::Retry(anyhow!("{what} error: {e}"))
            })?;
        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .ok_or_else(|| Fetch::Final(anyhow!("{what} redirected nowhere")))?;
            redirects += 1;
            if redirects > MAX_REDIRECTS {
                return Err(Fetch::Final(anyhow!("{what} too many redirects")));
            }
            url = url
                .join(location)
                .map_err(|e| Fetch::Final(anyhow!("{what} bad redirect: {e}")))?;
            continue;
        }
        break resp;
    };
    let status = resp.status();
    let fields = format!("{fields} responseStatus={status}");
    match status.as_u16() {
        200 => {}
        403 => {
            ctx.trace.error(&format!("{what} forbidden  {fields}"));
            return Err(Fetch::Final(anyhow!("{what} forbidden ({status})")));
        }
        401 => {
            ctx.trace.error(&format!("{what} unauthorized  {fields}"));
            return Err(Fetch::Final(anyhow!("{what} unauthorized ({status})")));
        }
        404 => {
            ctx.trace.error(&format!("{what} not found  {fields}"));
            return Err(Fetch::Final(anyhow!("{what} not found")));
        }
        _ => {
            ctx.trace.warning(&format!("{what} failed  {fields}"));
            return Err(Fetch::Retry(anyhow!("{what} failed ({status})")));
        }
    }
    if resp.content_length().is_some_and(|n| n > MAX_STAGED) {
        return Err(Fetch::Final(anyhow!("{what} {}", too_large(MAX_STAGED))));
    }
    let mut file = tokio::fs::File::from_std(create(dest).map_err(Fetch::Final)?);
    let mut size = 0u64;
    let mut resp = resp;
    loop {
        let chunk = cancelable(ctx, resp.chunk())
            .await
            .map_err(Fetch::Final)?
            .map_err(|e| Fetch::Retry(anyhow!("{what} error: {e}")))?;
        let Some(chunk) = chunk else { break };
        size = size.saturating_add(chunk.len() as u64);
        if size > MAX_STAGED {
            return Err(Fetch::Final(anyhow!("{what} {}", too_large(MAX_STAGED))));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| Fetch::Final(anyhow!("writing {}: {e}", dest.display())))?;
    }
    file.flush()
        .await
        .map_err(|e| Fetch::Final(anyhow!("writing {}: {e}", dest.display())))?;
    ctx.trace.print(&format!("{what} ok  {fields}"));
    Ok(())
}

/// `upload_artifacts_on_success` or `_on_failure`: each artifact whose `when` applies,
/// archived and uploaded, in the spec's order. Every artifact has an outcome, skipped ones
/// included; `Err` when an upload failed, which fails the job. As gitlab-runner's script
/// stops at the first failing upload, the artifacts after a failed one are not tried and
/// read as skipped.
pub async fn upload(ctx: &StageCtx<'_>, succeeded: bool) -> (Vec<ArtifactOutcome>, Result<()>) {
    let mut outcomes = Vec::with_capacity(ctx.job.artifacts.len());
    let (client, mut failed) = match client(ctx) {
        Ok(c) => (Some(c), None),
        Err(e) => (None, Some(e)),
    };
    for (i, a) in ctx.job.artifacts.iter().enumerate() {
        let outcome = |state| ArtifactOutcome {
            name: a.name.clone(),
            artifact_type: a.artifact_type.clone(),
            state,
        };
        let Some(client) = client.as_ref().filter(|_| failed.is_none()) else {
            outcomes.push(outcome(UploadState::Skipped));
            continue;
        };
        if !a.when.applies(succeeded) || !selects(a) || ctx.job.server_url.is_empty() {
            outcomes.push(outcome(UploadState::Skipped));
            continue;
        }
        ctx.trace.notice("Uploading artifacts...");
        let state = match upload_one(ctx, client, a, i).await {
            Ok(state) => state,
            Err(e) => {
                ctx.trace.error(&format!("{e:#}"));
                failed = Some(e.context(format!("uploading the artifact {:?}", a.name)));
                UploadState::Failed
            }
        };
        if state == UploadState::TooLarge {
            failed = Some(anyhow!(
                "uploading the artifact {:?}: too large for GitLab",
                a.name
            ));
        }
        outcomes.push(outcome(state));
    }
    (outcomes, failed.map_or(Ok(()), Err))
}

/// The name gitlab-runner gives the file it uploads (`artifactFilename`).
fn artifact_filename(name: &str, format: ArtifactFormat) -> String {
    let base = name.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
    let base = match base {
        "" | "." => "default",
        b => b,
    };
    match format {
        ArtifactFormat::Zip | ArtifactFormat::ZipZstd => format!("{base}.zip"),
        ArtifactFormat::Gzip => format!("{base}.gz"),
        ArtifactFormat::TarZstd => format!("{base}.tar.zst"),
        ArtifactFormat::Raw => base.to_string(),
    }
}

fn format_name(format: ArtifactFormat) -> &'static str {
    match format {
        ArtifactFormat::Zip => "zip",
        ArtifactFormat::Gzip => "gzip",
        ArtifactFormat::Raw => "raw",
        ArtifactFormat::ZipZstd => "zipzstd",
        ArtifactFormat::TarZstd => "tarzstd",
    }
}

async fn upload_one(
    ctx: &StageCtx<'_>,
    client: &reqwest::Client,
    a: &ArtifactSpec,
    index: usize,
) -> Result<UploadState> {
    if matches!(a.format, ArtifactFormat::ZipZstd | ArtifactFormat::TarZstd) {
        bail!(
            "artifact format {} is not supported on vk nodes yet",
            format_name(a.format)
        );
    }
    // The guest's tar streams into the conversion; the archive is kept, as a zip is patched
    // as it is written and the upload is sized and may be sent again.
    let archive_path = ctx.scratch.join(format!("artifact-{index}.archive"));
    let out = async {
        let sel = Selection {
            paths: a.paths.clone(),
            exclude: a.exclude.clone(),
            untracked: a.untracked,
        };
        let (archive_out, format) = (archive_path.clone(), a.format);
        let (mut tar, converted) =
            transfer::into_blocking(move |input| convert(input, &archive_out, format));
        let produced = cancelable(
            ctx,
            guest::archive(
                &ctx.addr,
                ctx.user.as_deref(),
                &ctx.project_dir,
                &sel,
                &mut tar,
                ctx.trace,
            ),
        )
        .await?;
        drop(tar);
        let converted = transfer::joined(converted)
            .await
            .context("archiving the artifact");
        if matches!(produced, Ok(0)) {
            ctx.trace.error("No files to upload");
            return Ok(UploadState::Skipped);
        }
        let (found, warnings) = transfer::both(produced, converted)?;
        for w in warnings {
            ctx.trace.warning(&w);
        }
        ctx.trace.print(&format!(
            "{}: found {found} matching artifact files and directories",
            a.paths.join(", ")
        ));
        send(ctx, client, a, &archive_path).await
    }
    .await;
    remove(&archive_path);
    out
}

/// The guest's tar read from `tar` as `format` at `out`. Returns the entries it left out.
fn convert(tar: &mut dyn Read, out: &Path, format: ArtifactFormat) -> Result<Vec<String>> {
    let input = std::io::BufReader::with_capacity(CHUNK, tar);
    let mut file = Capped::new(create(out)?, MAX_STAGED);
    let mut warnings = Vec::new();
    let mut warn = |w| warnings.push(w);
    match format {
        ArtifactFormat::Zip => {
            let mut w = std::io::BufWriter::new(&mut file);
            zip::tar_to_zip(input, &mut w, &mut warn)?;
            w.flush()?;
        }
        ArtifactFormat::Gzip => {
            zip::tar_to_gzip(input, std::io::BufWriter::new(&mut file), &mut warn)?;
        }
        ArtifactFormat::Raw => {
            zip::tar_to_raw(input, std::io::BufWriter::new(&mut file), &mut warn)?
        }
        ArtifactFormat::ZipZstd | ArtifactFormat::TarZstd => {
            bail!("artifact format {} is not supported", format_name(format))
        }
    }
    Ok(warnings)
}

/// How one upload attempt ended (`common.UploadState`).
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Created,
    Redirected(String),
    Forbidden,
    TooLarge,
    Unavailable(Option<Duration>),
    Failed(String),
}

/// POST the archive, retrying as `artifacts-uploader` does. A 307 is followed as
/// gitlab-runner follows it, with two exceptions: one from https to http is refused, and the
/// job's token is sent only to GitLab's own origin (gitlab-runner sends it wherever the
/// redirect points).
async fn send(
    ctx: &StageCtx<'_>,
    client: &reqwest::Client,
    a: &ArtifactSpec,
    archive: &Path,
) -> Result<UploadState> {
    let home = api_base(&ctx.job.server_url)?;
    let home_url = reqwest::Url::parse(&home).context("bad GitLab URL")?;
    let mut base = home;
    let mut token = Some(ctx.job.token.as_str());
    let filename = artifact_filename(&a.name, a.format);
    let what = match a.artifact_type.as_str() {
        "" => "Uploading artifacts to coordinator...".to_string(),
        t => format!("Uploading artifacts as {t:?} to coordinator..."),
    };
    let mut tries = 0;
    loop {
        tries += 1;
        let url = upload_url(&base, ctx.job.job.id, a);
        let sent = cancelable(ctx, post(client, &url, token, &filename, archive)).await??;
        let status = |s: &str| {
            format!(
                "{what} {s}  id={} token={}",
                ctx.job.job.id,
                short_token(&ctx.job.token)
            )
        };
        let (retry_in, max) = match sent {
            Sent::Created => {
                ctx.trace.print(&status("201 Created"));
                return Ok(UploadState::Uploaded);
            }
            Sent::TooLarge => {
                ctx.trace.error(&status("413 Payload Too Large"));
                return Ok(UploadState::TooLarge);
            }
            Sent::Forbidden => {
                ctx.trace.error(&status("403 Forbidden"));
                bail!("{what} forbidden");
            }
            Sent::Redirected(location) => {
                let (to, home) = redirected(&home_url, &location)?;
                base = to;
                token = home.then_some(ctx.job.token.as_str());
                (Duration::ZERO, UPLOAD_TRIES)
            }
            Sent::Unavailable(after) => {
                ctx.trace.error(&status("503 Service Unavailable"));
                (
                    after.unwrap_or(Duration::from_secs(1)).min(MAX_RETRY_AFTER),
                    UNAVAILABLE_TRIES,
                )
            }
            Sent::Failed(why) => {
                ctx.trace.warning(&status(&why));
                (Duration::from_secs(1), UPLOAD_TRIES)
            }
        };
        if tries >= max {
            bail!("{what} failed after {tries} attempts");
        }
        cancelable(ctx, tokio::time::sleep(retry_in)).await?;
    }
}

/// `<server_url>/api/v4`, as gitlab-runner's client roots every request.
fn api_base(server_url: &str) -> Result<String> {
    let url = server_url.trim_end_matches('/');
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        bail!("GitLab's URL {url:?} is not http(s)");
    }
    Ok(format!("{url}/api/v4"))
}

/// Where a 307 to `location` sends the upload: the redirect's scheme and host, under which
/// the request is made again (`handleRedirect` drops its path and query), and whether that is
/// GitLab's own origin, `home`. A redirect from https to http is refused.
fn redirected(home: &reqwest::Url, location: &str) -> Result<(String, bool)> {
    let url = home
        .join(location)
        .with_context(|| format!("parsing the redirect {location:?}"))?;
    if home.scheme() == "https" && url.scheme() != "https" {
        bail!("refusing the redirect from https to {location:?}");
    }
    let host = url.host_str().context("the redirect names no host")?;
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let base = api_base(&format!("{}://{host}{port}", url.scheme()))?;
    Ok((base, origin(&url) == origin(home)))
}

/// `POST jobs/<id>/artifacts?<query>`, its query as Go's `url.Values.Encode` writes it:
/// keys sorted, values form-escaped (`uploadRawArtifactsQuery`).
fn upload_url(base: &str, job_id: u64, a: &ArtifactSpec) -> String {
    let query: Vec<String> = [
        ("artifact_format", format_name(a.format)),
        ("artifact_type", a.artifact_type.as_str()),
        ("expire_in", a.expire_in.as_str()),
    ]
    .iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| format!("{k}={}", query_escape(v)))
    .collect();
    format!("{base}/jobs/{job_id}/artifacts?{}", query.join("&"))
}

/// Go's `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b))
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The multipart framing around the archive: the `file` field, as Go's
/// `multipart.Writer.CreateFormFile` writes it.
fn multipart(boundary: &str, filename: &str) -> (Vec<u8>, Vec<u8>) {
    let escaped = filename.replace('\\', "\\\\").replace('"', "\\\"");
    let head = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
         filename=\"{escaped}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    let tail = format!("\r\n--{boundary}--\r\n");
    (head.into_bytes(), tail.into_bytes())
}

fn boundary() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("vk{nanos:032x}{:08x}", std::process::id())
}

/// One upload attempt: the archive streamed from disk inside its multipart framing.
async fn post(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    filename: &str,
    archive: &Path,
) -> Result<Sent> {
    let boundary = boundary();
    let (head, tail) = multipart(&boundary, filename);
    let file = File::open(archive).context("opening the archive")?;
    let size = file.metadata().context("reading the archive")?.len();
    let len = size + head.len() as u64 + tail.len() as u64;
    let body = reqwest::Body::wrap_stream(body_stream(head, file, tail));
    let mut req = client.post(url);
    if let Some(token) = token {
        req = req.header("JOB-TOKEN", token);
    }
    let resp = match req
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(reqwest::header::CONTENT_LENGTH, len)
        .body(body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => return Ok(Sent::Failed(format!("error: {e}"))),
    };
    let status = resp.status();
    Ok(match status.as_u16() {
        201 => Sent::Created,
        307 => match resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|l| l.to_str().ok())
        {
            Some(l) => Sent::Redirected(l.to_string()),
            None => Sent::Failed(format!("{status} empty location")),
        },
        403 => Sent::Forbidden,
        413 => Sent::TooLarge,
        503 => Sent::Unavailable(
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs),
        ),
        _ => Sent::Failed(message(resp).await),
    })
}

/// An error answer's text: its JSON `message` where it has one, else its status
/// (`getMessageFromJSONResponse`).
async fn message(mut resp: reqwest::Response) -> String {
    let status = resp.status().to_string();
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() >= MAX_ERROR_BODY {
            break;
        }
    }
    match serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("message").cloned())
    {
        Some(serde_json::Value::String(m)) => m,
        Some(other) => other.to_string(),
        None => status,
    }
}

/// The multipart body: `head`, the file in chunks read off the runtime, then `tail`.
fn body_stream(
    head: Vec<u8>,
    file: File,
    tail: Vec<u8>,
) -> impl futures::Stream<Item = std::io::Result<Bytes>> + Send + 'static {
    enum Part {
        Head(Vec<u8>, File, Vec<u8>),
        Body(File, Vec<u8>),
        Done,
    }
    futures::stream::unfold(Part::Head(head, file, tail), |part| async move {
        match part {
            Part::Head(head, file, tail) => Some((Ok(Bytes::from(head)), Part::Body(file, tail))),
            Part::Body(mut file, tail) => {
                let read = tokio::task::spawn_blocking(move || {
                    let mut buf = vec![0u8; CHUNK];
                    let n = file.read(&mut buf)?;
                    buf.truncate(n);
                    Ok::<_, std::io::Error>((file, buf))
                })
                .await;
                match read {
                    Ok(Ok((_, buf))) if buf.is_empty() => Some((Ok(Bytes::from(tail)), Part::Done)),
                    Ok(Ok((file, buf))) => Some((Ok(Bytes::from(buf)), Part::Body(file, tail))),
                    Ok(Err(e)) => Some((Err(e), Part::Done)),
                    Err(e) => Some((Err(std::io::Error::other(e)), Part::Done)),
                }
            }
            Part::Done => None,
        }
    })
}

/// GitLab's client: the system's roots plus the chain the daemon verified GitLab with, and no
/// redirect followed on its own (each is handled where the token's destination matters).
fn client(ctx: &StageCtx<'_>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(30))
        .timeout(UPLOAD_TIMEOUT);
    if let Some(pem) = &ctx.job.server_ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .context("reading GitLab's CA chain")?;
        b = b.tls_certs_merge(certs);
    }
    b.build().context("building the GitLab client")
}

/// Scheme, host and port: where a request goes, for whether it may carry the token.
fn origin(url: &reqwest::Url) -> (String, Option<String>, Option<u16>) {
    (
        url.scheme().to_string(),
        url.host_str().map(str::to_string),
        url.port_or_known_default(),
    )
}

/// gitlab-runner's `ShortenToken` for a job token: its prefix dropped, nine characters kept,
/// made to start and end alphanumeric.
fn short_token(token: &str) -> String {
    let rest = match token.find("glcbt-") {
        Some(at)
            if token[..at]
                .strip_suffix('-')
                .unwrap_or(&token[..at])
                .bytes()
                .all(|b| b.is_ascii_alphanumeric()) =>
        {
            &token[at + "glcbt-".len()..]
        }
        _ => token,
    };
    let mut s: Vec<u8> = rest.bytes().take(9).collect();
    if s.first().is_some_and(|b| !b.is_ascii_alphanumeric()) {
        s.insert(0, b'r');
        s.pop();
    }
    if let Some(last) = s.last_mut()
        && !last.is_ascii_alphanumeric()
    {
        *last = b'r';
    }
    String::from_utf8_lossy(&s).into_owned()
}

/// `fut`, or an error once the job is canceled.
async fn cancelable<T>(ctx: &StageCtx<'_>, fut: impl std::future::Future<Output = T>) -> Result<T> {
    tokio::select! {
        out = fut => Ok(out),
        () = ctx.cancel.cancelled() => bail!("canceled"),
    }
}

fn remove(path: &Path) {
    // Scratch space, which the job's cleanup removes anyway.
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests;
