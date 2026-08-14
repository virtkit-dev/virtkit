//! Replace a running virtkit binary with a published GitHub release build.
//!
//! A release ships each host tool as one static asset next to the `sha256sum` sidecar
//! CI generates for it, and the tools carry what they need inside them — so an update is
//! a single file: download it, check it against the published digest, and rename it over
//! the running binary. The rename is atomic and leaves the live process untouched (it
//! keeps the old inode; only the directory entry moves), so an update never interrupts
//! work already in flight — and a long-lived server goes on serving the old build until
//! it is restarted.
//!
//! Nothing is written before the user confirms the version they are moving to, and the
//! replacement only happens once the download hashes to the digest published beside it
//! and the new binary reports its own version when run. Both gates are integrity checks
//! against one release rather than proof of who published it: they catch a corrupted or
//! truncated transfer and a build that cannot run here, which is why the tag a release is
//! looked up by has to be trusted in its own right — see `release_tag`. [`Tool::check`]
//! stops after resolving the release, making it a read-only query for what is available.
//!
//! Which binary is replaced is the caller's [`Tool`]. The repository releases are looked
//! up in is deliberately not part of it: both gates are satisfied by any release that is
//! internally consistent, so a caller able to name the publisher could point an update at
//! a repository of its own and have it install cleanly.

use std::cmp::Ordering;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

/// The repository releases are published from.
const REPO: &str = "virtkit-dev/virtkit";
/// GitHub's REST API root. Threaded through as an argument rather than read from this
/// constant at each call site, so the tests can aim the same code at a local server.
const API: &str = "https://api.github.com";
/// Mode to install with when the binary being replaced has none to copy.
const INSTALL_MODE: u32 = 0o755;
/// A sidecar is one `sha256sum` line, and a release JSON a few kilobytes of it. Reading
/// an unbounded body into memory to find out it is neither is how a hostile mirror
/// exhausts the host's RAM.
const MAX_SIDECAR: usize = 4096;
const MAX_RELEASE_JSON: usize = 1024 * 1024;
/// The largest asset a release can plausibly ship — the binaries are tens of megabytes.
/// The download's own length check is relative to what the release announced, so without
/// a ceiling on that number a release claiming half a terabyte would be honoured.
const MAX_ASSET: u64 = 512 * 1024 * 1024;
/// Connect and per-read timeouts. `--check` is meant for cron and login banners, so a
/// black-holed endpoint has to fail instead of hanging forever; a per-read deadline
/// bounds a stalled connection without capping how long a large download may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The binary an update replaces.
#[derive(Clone, Copy, Debug)]
pub struct Tool {
    /// Its name: the release asset it ships as, and the word its own output uses (both
    /// the message about it and the `<name> update` command line that produced it). A
    /// plain file name — it is also the download's own, beside the binary being replaced.
    pub name: &'static str,
    /// The version it was built as — the *caller's* `CARGO_PKG_VERSION`, which is what a
    /// release's tag is compared against to decide whether installing it moves forward.
    pub version: &'static str,
}

/// What [`Tool::update`] did, for a caller with something to add afterwards: the binary on
/// disk changing is not the same as the change taking effect.
#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    /// the release is the version already installed; nothing was written
    AlreadyCurrent,
    /// the user declined at the confirmation prompt; nothing was written
    Declined,
    /// the release build is now the binary on disk
    Installed,
}

/// The subset of GitHub's release JSON we read.
#[derive(serde::Deserialize)]
struct ApiRelease {
    tag_name: String,
    assets: Vec<ApiAsset>,
}

#[derive(serde::Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// A release's asset for one tool, resolved and ready to fetch.
#[derive(Debug)]
struct Target {
    tag: String,
    url: String,
    /// download URL of the asset's `sha256sum` sidecar
    digest_url: String,
    size: u64,
}

/// How a release relates to the version this binary was built as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// the release is the version already installed
    Same,
    /// strictly newer — the only case `--check` reports as an update waiting
    Newer,
    /// a different version that is not newer: an older release — installable, which is
    /// what naming one on the command line is for — or a tag carrying no version to
    /// order at all, which [`Tool::smoke_test`] then refuses because the build cannot
    /// report the tag's own name as its version.
    Other,
}

/// A tag name checked to be safe in the API URL's path. Naming a release goes through
/// [`release_tag`], the only constructor, so no later caller can route an unchecked
/// string into the URL.
#[derive(Debug, PartialEq, Eq)]
struct ReleaseTag(String);

impl std::fmt::Display for ReleaseTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What both entry points resolve before deciding anything: the binary they would
/// replace, the release on offer, and how the two relate.
struct Plan {
    exe: PathBuf,
    client: reqwest::Client,
    target: Target,
    step: Step,
}

impl Tool {
    /// Move this binary to `tag`'s release build, or to the latest release when no tag is
    /// given. Prompts before replacing it unless `assume_yes`; the [`Outcome`] says whether
    /// anything was written.
    pub async fn update(&self, tag: Option<&str>, assume_yes: bool) -> Result<Outcome> {
        let plan = self.plan(API, tag).await?;
        if plan.step == Step::Same {
            println!(
                "{} is already at {} ({})",
                self.name,
                self.version,
                plan.exe.display()
            );
            return Ok(Outcome::AlreadyCurrent);
        }
        // The download lands in the installed binary's own directory, so publishing it is
        // a rename on the same filesystem rather than a copy.
        let dir = plan
            .exe
            .parent()
            .with_context(|| format!("{} has no parent directory", plan.exe.display()))?;

        // The pre-confirmation summary is interactive framing, so it goes to stderr with
        // the prompt (which is unreadable without it) and leaves stdout to the outcome.
        let aside = match plan.step {
            // An upgrade is the expected case and needs no aside; `Same` returned above.
            Step::Newer | Step::Same => "",
            Step::Other => " — not a newer release",
        };
        eprintln!(
            "{} {} -> {} ({}){aside}",
            self.name,
            self.version,
            plan.target.tag,
            HumanBytes(plan.target.size)
        );
        eprintln!("  replacing {}", plan.exe.display());
        if !assume_yes && !self.confirm()? {
            eprintln!("update cancelled");
            return Ok(Outcome::Declined);
        }

        self.install(&plan.client, &plan.target, &plan.exe, dir)
            .await?;
        println!("{} updated to {}", self.name, plan.target.tag);
        Ok(Outcome::Installed)
    }

    /// Report how the release `tag` names — or the latest one when no tag is given —
    /// compares to this binary, without downloading it. Returns true only for a strictly
    /// newer release, which the caller turns into the exit code a script can branch on.
    pub async fn check(&self, tag: Option<&str>) -> Result<bool> {
        let plan = self.plan(API, tag).await?;
        // An explicit tag is whatever the user named; only the default is "the latest".
        let label = match tag {
            Some(_) => "release",
            None => "latest release",
        };
        let found = &plan.target.tag;
        println!("{} {} ({})", self.name, self.version, plan.exe.display());
        match plan.step {
            Step::Same => {
                println!("  {label} {found} — up to date");
                Ok(false)
            }
            Step::Newer => {
                // Name the version in the hint, so the line works as-is for a release the
                // user asked about by name.
                let hint = match tag {
                    Some(_) => format!("{} update {found}", self.name),
                    None => format!("{} update", self.name),
                };
                println!(
                    "  {label} {found} available ({}) — run `{hint}` to install it",
                    HumanBytes(plan.target.size)
                );
                Ok(true)
            }
            // Not an update: exit 0, so a `--check` in cron or a login banner stays quiet
            // about a release older than the build in place, and about a tag whose version
            // cannot be ordered against it.
            Step::Other => {
                println!("  {label} {found} is not newer than this build");
                Ok(false)
            }
        }
    }

    /// Resolve the release `tag` names — or the latest published one — and work out what
    /// installing it would do to this binary.
    async fn plan(&self, api: &str, tag: Option<&str>) -> Result<Plan> {
        let exe = std::env::current_exe()
            .with_context(|| format!("locating the running {} binary", self.name))?;
        let client = self.http_client()?;
        let target = self.resolve(&client, api, tag).await?;
        let step = step(self.version, &target.tag);
        Ok(Plan {
            exe,
            client,
            target,
            step,
        })
    }

    /// An HTTP client identifying itself: GitHub's API rejects requests without a
    /// `User-Agent`.
    fn http_client(&self) -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .user_agent(format!("{}/{}", self.name, self.version))
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .context("building the HTTP client")
    }

    /// Resolve a release — `tag`'s, or the latest published one — to this tool's asset.
    async fn resolve(
        &self,
        client: &reqwest::Client,
        api: &str,
        tag: Option<&str>,
    ) -> Result<Target> {
        // The user's tag crosses the trust boundary once, here; the checked form is what
        // both the URL and the error message below are built from.
        let tag = tag.map(release_tag).transpose()?;
        let url = api_url(api, tag.as_ref());
        let resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .with_context(|| format!("querying {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            if rate_limited(&resp) {
                bail!(
                    "GitHub's API rate limit is exhausted for this host (HTTP {status}) — retry later"
                );
            }
            // 404 on the tags endpoint is the common case: a version that was never
            // released, or spelled differently than the tag.
            match &tag {
                Some(t) => bail!("no release {t} in {REPO} (HTTP {status})"),
                None => bail!("no latest release in {REPO} (HTTP {status})"),
            }
        }
        let body = bounded_body(resp, MAX_RELEASE_JSON, &url).await?;
        let release: ApiRelease = serde_json::from_slice(&body)
            .with_context(|| format!("parsing the release JSON from {url}"))?;
        // The tag goes straight into the confirmation prompt the user answers, so it may not
        // carry the control bytes that would let it rewrite the line around the question.
        if release.tag_name.chars().any(char::is_control) {
            bail!("the release's tag name is not printable");
        }
        let asset = pick(&release.assets, self.name)?;
        let digest = pick(&release.assets, &format!("{}.sha256", self.name))?;
        if asset.size > MAX_ASSET {
            bail!(
                "the release's {name} asset is {} — larger than a {name} build can be",
                HumanBytes(asset.size),
                name = self.name,
            );
        }
        // The release told us where its assets live; require them on the scheme the API was
        // itself reached over, so a response cannot quietly move the transfer to cleartext —
        // the sidecar would move with it, leaving the digest gate none the wiser.
        let scheme = format!("{}://", api.split_once("://").map_or("https", |(s, _)| s));
        for a in [asset, digest] {
            if !a.browser_download_url.starts_with(&scheme) {
                bail!("the release's {} asset is not served over {scheme}", a.name);
            }
        }
        Ok(Target {
            tag: release.tag_name,
            url: asset.browser_download_url.clone(),
            digest_url: digest.browser_download_url.clone(),
            size: asset.size,
        })
    }

    /// Make `target`'s release build the binary at `exe`. Every failure — a bad download, a
    /// gate it does not pass, a rename that cannot happen — leaves `exe` as it was and
    /// nothing extra in `dir`.
    async fn install(
        &self,
        client: &reqwest::Client,
        target: &Target,
        exe: &Path,
        dir: &Path,
    ) -> Result<()> {
        // `current_exe` is the on-disk *pathname*, not the `/proc/self/exe` magic link (see
        // `spawn::self_exe` in vk-driver): once the file this process was loaded from is
        // unlinked, the kernel reports it as `…/vk (deleted)`, and renaming onto that would
        // install a binary nobody runs while reporting success. Checked before the download,
        // so a pointless 40-megabyte transfer is not how the user finds out.
        if !exe.is_file() {
            bail!(
                "{} is gone — {name} was replaced while this ran; rerun {name} update",
                exe.display(),
                name = self.name,
            );
        }
        // A dotfile beside the installed binary: same filesystem as `exe`, so publishing it
        // is a rename. The pid keeps two updates running at once off each other's file.
        //
        // That path is re-resolved by the exec, the rename and the cleanup rather than held
        // as an fd, which `rust.md` says to treat as a TOCTOU bug until argued otherwise:
        // winning the race needs write access to `dir`, and whoever has that can replace
        // the binary outright without going near this code.
        let tmp = dir.join(self.tmp_name());
        // Created here rather than inside `download`, so the cleanup below covers exactly the
        // window in which this file is ours: a path that already exists is refused untouched,
        // leaving the file for the user the error tells to remove it.
        let file = self.create_tmp(&tmp, dir)?;
        let outcome = match self
            .download(client, target, file, &tmp, mode_of(exe))
            .await
        {
            Ok(()) => publish(&tmp, exe, dir),
            Err(e) => Err(e),
        };
        if outcome.is_err() {
            // Best-effort: an unverified or unpublished binary must not be left lying next
            // to the installed one, but the original error is what the user needs to see.
            let _ = fs::remove_file(&tmp);
        }
        outcome
    }

    /// The dotfile this process downloads into, beside the binary it is replacing.
    fn tmp_name(&self) -> String {
        format!(".{}-update.{}", self.name, std::process::id())
    }

    /// Create the file the download lands in, refusing to reuse anything already at that
    /// path: 0600 while the contents are unverified — nothing else may execute this file
    /// before the digest gate has passed — and `create_new`, so a symlink or a file planted
    /// here is refused rather than written through.
    fn create_tmp(&self, tmp: &Path, dir: &Path) -> Result<fs::File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => anyhow!(
                    "{} already exists — an interrupted {} update left it behind, and nothing \
                     here reuses it; it is safe to remove",
                    tmp.display(),
                    self.name
                ),
                _ => anyhow::Error::new(e).context(format!(
                    "creating {} (is {} writable?)",
                    tmp.display(),
                    dir.display()
                )),
            })
    }

    /// Download `target` into `tmp` and put it through both gates: it must hash to the
    /// digest published beside it, and report its own version when run. Returns with `tmp`
    /// verified, executable and durable — ready to be renamed into place.
    async fn download(
        &self,
        client: &reqwest::Client,
        target: &Target,
        mut file: fs::File,
        tmp: &Path,
        mode: u32,
    ) -> Result<()> {
        let want = self.digest(client, target).await?;
        let resp = client
            .get(&target.url)
            .send()
            .await
            .with_context(|| format!("downloading {}", target.url))?
            .error_for_status()
            .with_context(|| format!("downloading {}", target.url))?;
        let bar = progress(target.size);
        let got = stream_asset(resp, &mut file, tmp, target, &bar).await;
        // Cleared whether or not the body arrived, so a failure's message is not printed
        // under a stalled progress bar.
        bar.finish_and_clear();
        let got = got?;

        if got.as_slice() != want {
            let shown = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
            bail!(
                "{} does not match the published digest (got {}, want {})",
                target.url,
                shown(&got),
                shown(&want)
            );
        }
        // Made executable here rather than at creation: `open(2)` masks its mode argument
        // with the umask, so asking for 0755 there installs a 0700 binary under `umask 077`.
        // `fchmod` through the open fd, so there is no path to re-resolve.
        file.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode on {}", tmp.display()))?;
        // `sync_all`, not `flush`: `File`'s flush is a no-op, so without this a host crash
        // just after the rename could leave a truncated binary behind — and for `vk` that
        // is the tool that would otherwise repair it.
        file.sync_all()
            .with_context(|| format!("flushing {} to disk", tmp.display()))?;
        // Closed before the exec below, not merely at the end of scope: `execve` refuses a
        // file any process still holds open for writing (ETXTBSY).
        drop(file);

        self.smoke_test(tmp, version_of(&target.tag))
    }

    /// This tool's expected sha256, from the sidecar CI publishes beside its asset.
    async fn digest(&self, client: &reqwest::Client, target: &Target) -> Result<[u8; 32]> {
        let resp = client
            .get(&target.digest_url)
            .send()
            .await
            .with_context(|| format!("downloading {}", target.digest_url))?
            .error_for_status()
            .with_context(|| format!("downloading {}", target.digest_url))?;
        let body = bounded_body(resp, MAX_SIDECAR, &target.digest_url).await?;
        let text = std::str::from_utf8(&body)
            .with_context(|| format!("{} is not text", target.digest_url))?;
        parse_digest(text, self.name)
            .with_context(|| format!("parsing the digest from {}", target.digest_url))
    }

    /// Confirm the downloaded binary runs on this host and is the version we asked for:
    /// the digest proves the transfer was faithful, not that the release is usable here
    /// (a foreign architecture hashes fine and cannot exec). Runs before the rename, so
    /// a binary that fails this never becomes the installed one.
    fn smoke_test(&self, path: &Path, version: &str) -> Result<()> {
        let out = run_version(path).map_err(|e| {
            // Which errno this is decides what went wrong, and the causes are nothing alike:
            // a release built for another architecture (ENOEXEC), a file some process still
            // holds open for writing (ETXTBSY, and `run_version` has already waited it out),
            // a host with no room left to fork (EAGAIN). Only the first two name a cause worth
            // reporting — offering one for the rest buries the errno under a wrong answer.
            let hint = match e.raw_os_error() {
                Some(libc::ENOEXEC) => " (is the release built for this architecture?)",
                Some(libc::ETXTBSY) => {
                    " (something is still holding the download open for writing)"
                }
                _ => "",
            };
            anyhow::Error::new(e).context(format!("running {} --version{hint}", path.display()))
        })?;
        // Non-UTF-8 output is not a version string: fall through to the error below with
        // it empty rather than mangling the bytes to report them.
        let reported = std::str::from_utf8(&out.stdout).unwrap_or_default();
        // A whole token, not a substring: `vk --version` prints `vk-driver <version> (<hash>)`,
        // and `contains` would let a binary reporting `0.30.0` satisfy a request for `0.3`.
        let named = reported.split_whitespace().any(|t| t == version);
        if !out.status.success() || !named {
            bail!(
                "the downloaded {} did not report version {version} ({}, output: {})",
                self.name,
                out.status,
                reported.trim()
            );
        }
        Ok(())
    }

    /// Ask on stderr, read the answer on stdin. Anything but an explicit yes declines,
    /// and without a terminal to ask at there is no implicit yes — `--yes` is how a
    /// script opts in.
    fn confirm(&self) -> Result<bool> {
        if !std::io::stdin().is_terminal() {
            bail!(
                "{name} update needs a terminal to confirm at; pass --yes to update unattended",
                name = self.name
            );
        }
        eprint!("proceed? [y/N] ");
        std::io::stderr().flush().context("writing the prompt")?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("reading the answer")?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
    }
}

/// The API endpoint for a release: the one `tag` names, or the latest published one.
fn api_url(api: &str, tag: Option<&ReleaseTag>) -> String {
    match tag {
        Some(t) => format!("{api}/repos/{REPO}/releases/tags/{t}"),
        None => format!("{api}/repos/{REPO}/releases/latest"),
    }
}

/// A throttled API response, told apart from a plain refusal: unauthenticated calls get
/// 60 an hour per IP, which a per-minute `--check` or a whole NATed office runs through,
/// and reporting that as a missing release sends the user hunting the wrong problem.
/// GitHub answers 429, or 403 with the remaining quota at zero.
fn rate_limited(resp: &reqwest::Response) -> bool {
    let headers = resp.headers();
    let exhausted = headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "0");
    // Either signal on a 403: the hourly limit zeroes the quota header, while the
    // secondary (burst) limit leaves it alone and answers with `retry-after`.
    resp.status() == 429
        || (resp.status() == 403 && (exhausted || headers.contains_key("retry-after")))
}

/// The named asset of a release, or an error naming what the release does carry.
fn pick<'a>(assets: &'a [ApiAsset], name: &str) -> Result<&'a ApiAsset> {
    assets.iter().find(|a| a.name == name).with_context(|| {
        let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
        format!(
            "the release has no {name} asset (it has: {})",
            names.join(", ")
        )
    })
}

/// Swap the verified download in as `exe`, and make the swap durable: the directory
/// fsync is what keeps a host crash from leaving the entry pointing at nothing.
fn publish(tmp: &Path, exe: &Path, dir: &Path) -> Result<()> {
    fs::rename(tmp, exe)
        .with_context(|| format!("installing {} as {}", tmp.display(), exe.display()))?;
    // Best-effort, as in vk-driver's `vms::record_in`: the rename itself already succeeded,
    // and a host that cannot fsync its bin directory is no reason to report a failed update.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The mode to install with: whatever the binary being replaced carries, so an install
/// deliberately narrowed (a group-only 0750 `vk`) keeps its permissions instead of
/// being widened by an update. [`INSTALL_MODE`] when there is nothing to read.
fn mode_of(exe: &Path) -> u32 {
    fs::metadata(exe)
        // 0o777, not 0o7777: set-user-ID and set-group-ID are not carried onto bytes
        // that just arrived over the network, whatever the old binary was marked with.
        // The owner-execute bit is forced on so the result is always runnable — the
        // smoke test would otherwise fail on a mode it chose itself, blaming the release.
        .map(|m| (m.permissions().mode() & 0o777) | 0o100)
        .unwrap_or(INSTALL_MODE)
}

/// Write the asset's body into `file`, hashing it on the way past, and return the hash.
async fn stream_asset(
    resp: reqwest::Response,
    file: &mut fs::File,
    tmp: &Path,
    target: &Target,
    bar: &ProgressBar,
) -> Result<sha2::digest::Output<Sha256>> {
    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();
    let mut written = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("downloading {}", target.url))?;
        // Stop at the length the release announced: the digest can only be checked once
        // the whole body is down, and until then an endless response would fill the
        // filesystem the installed binary lives on.
        written = written.saturating_add(chunk.len() as u64);
        if written > target.size {
            bail!(
                "{} is longer than the {} bytes the release announced",
                target.url,
                target.size
            );
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .with_context(|| format!("writing {}", tmp.display()))?;
        bar.inc(chunk.len() as u64);
    }
    Ok(hasher.finalize())
}

/// Read a response body into memory, refusing one bigger than `max`: finding out that a
/// body is not what it claims to be must not cost the host its RAM.
async fn bounded_body(resp: reqwest::Response, max: usize, url: &str) -> Result<Vec<u8>> {
    let mut body: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("reading {url}"))?;
        body.extend_from_slice(&chunk);
        if body.len() > max {
            bail!("{url} is larger than {max} bytes");
        }
    }
    Ok(body)
}

/// Run `<path> --version`, waiting out a busy file rather than reporting it. Closing the
/// download's write fd is not enough on its own: a `fork` anywhere else in the process
/// inherits that open file, and the kernel counts the file open for writing — so `execve`
/// answers ETXTBSY — until that child reaches its own `exec`. Nothing here can stop the
/// fork, and the window it leaves is microseconds wide, so looking again beats failing a
/// download that is fine. A file held open for real still ends in ETXTBSY, once the
/// looking is done.
fn run_version(path: &Path) -> std::io::Result<std::process::Output> {
    // Ten looks 20ms apart — 180ms of waiting before a busy file is reported as busy.
    const ATTEMPTS: u32 = 10;
    const WAIT: Duration = Duration::from_millis(20);
    let run = || std::process::Command::new(path).arg("--version").output();
    for _ in 1..ATTEMPTS {
        match run() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => std::thread::sleep(WAIT),
            r => return r,
        }
    }
    // The last look is the verdict, whichever way it goes.
    run()
}

/// A download bar on stderr, or a silent one when stderr is not a terminal (so a
/// log or a CI job does not collect thousands of redraws).
fn progress(total: u64) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(total);
    if let Ok(style) = ProgressStyle::with_template(
        "  downloading [{bar:30}] {bytes}/{total_bytes} {bytes_per_sec} {eta}",
    ) {
        bar.set_style(style.progress_chars("=> "));
    }
    bar
}

/// The version a release tag carries (`v0.29.0` -> `0.29.0`), for comparison
/// against the caller's own `CARGO_PKG_VERSION`.
fn version_of(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// What installing `tag` would do to a binary built as `current`.
fn step(current: &str, tag: &str) -> Step {
    let candidate = version_of(tag);
    match compare(candidate, current) {
        Some(Ordering::Equal) => Step::Same,
        Some(Ordering::Greater) => Step::Newer,
        Some(Ordering::Less) => Step::Other,
        // Nothing to order against: the same string is still the same release, and
        // anything else is not an update waiting.
        None if candidate == current => Step::Same,
        None => Step::Other,
    }
}

/// Order two `MAJOR.MINOR.PATCH` versions field by field. `None` when either side is
/// not all numeric fields — a prerelease suffix or a name like `nightly` has no
/// ordering against a release version, and inventing one is how a downgrade ends up
/// announced as an update.
fn compare(a: &str, b: &str) -> Option<Ordering> {
    let fields =
        |v: &str| -> Option<Vec<u64>> { v.split('.').map(|f| f.parse::<u64>().ok()).collect() };
    Some(fields(a)?.cmp(&fields(b)?))
}

/// The published tag for a user-given version: releases are tagged `v<version>`, so
/// accept `0.29.0` as well as `v0.29.0`; a tag of another shape passes through.
///
/// Restricted to tag-shaped tokens because this lands in the API URL's path, where the
/// URL parser resolves `..` segments: a `/` in it would silently retarget the query at
/// another repository's releases, and both of this crate's gates would then pass —
/// that release's sidecar matches its own asset, and its binary reports its own
/// version. So the tag is the trust boundary, and it is checked here.
fn release_tag(arg: &str) -> Result<ReleaseTag> {
    let shaped = !arg.is_empty()
        && !arg.starts_with('.')
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'));
    if !shaped {
        bail!("{arg:?} is not a version or a tag name");
    }
    Ok(ReleaseTag(
        if arg.starts_with(|c: char| c.is_ascii_digit()) {
            format!("v{arg}")
        } else {
            arg.to_string()
        },
    ))
}

/// The digest of `name` in `sha256sum` output (`<hex>  <name>` lines), as the raw
/// bytes to compare a download's own hash against.
fn parse_digest(text: &str, name: &str) -> Result<[u8; 32]> {
    for line in text.lines() {
        let Some((sum, file)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        // sha256sum marks a binary-mode read with a single `*` before the name.
        let file = file.trim();
        if file.strip_prefix('*').unwrap_or(file) != name {
            continue;
        }
        return parse_sha256(sum).with_context(|| format!("{sum:?} is not a sha256"));
    }
    bail!("no {name} line in the sidecar")
}

/// 64 hex digits as the 32 bytes they encode (as vk-driver's `ensure::parse_uuid` does
/// for a UUID). The length and alphabet are checked first, so the slicing below is in
/// bounds and on ASCII boundaries.
fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::SocketAddr;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;

    use super::*;

    /// The tool under test, at the version [`FAKE_VK`] reports.
    const VK: Tool = Tool {
        name: "vk",
        version: "0.30.0",
    };
    /// A second tool in the same release, so what the asset name comes from is tested
    /// rather than assumed.
    const REGISTRY: Tool = Tool {
        name: "vk-registry",
        version: "0.30.0",
    };

    // A user-given version reaches the API as the tag CI publishes (`v<version>`),
    // whichever of the two forms they typed; other tag shapes pass through.
    #[test]
    fn release_tag_normalizes_a_bare_version() {
        assert_eq!(release_tag("0.29.0").unwrap().to_string(), "v0.29.0");
        assert_eq!(release_tag("v0.29.0").unwrap().to_string(), "v0.29.0");
        assert_eq!(release_tag("nightly").unwrap().to_string(), "nightly");
        assert_eq!(version_of("v0.29.0"), "0.29.0");
        assert_eq!(version_of("0.29.0"), "0.29.0");
    }

    // The tag lands in the API URL's path, so a `/` in it must never reach the URL: the
    // parser resolves `..` segments, and a retargeted query would be answered by a
    // release whose own digest and own version self-check both pass.
    #[test]
    fn release_tag_refuses_anything_that_could_retarget_the_url() {
        for bad in [
            "v0.1.0/../../../../../evil-owner/evil-repo/releases/latest",
            "../../evil-owner/evil-repo/releases/latest",
            "..",
            ".",
            "v1%2f..%2fx",
            "v1?per_page=1",
            "v1#frag",
            "v1 2",
            "",
        ] {
            assert!(release_tag(bad).is_err(), "{bad:?} must be refused");
        }
        // and the shapes that are allowed still build the endpoint they should. Only a
        // `ReleaseTag` can be passed here, so this is the whole surface reaching the URL.
        assert_eq!(
            api_url(API, Some(&release_tag("0.29.0").unwrap())),
            "https://api.github.com/repos/virtkit-dev/virtkit/releases/tags/v0.29.0"
        );
        assert_eq!(
            api_url(API, None),
            "https://api.github.com/repos/virtkit-dev/virtkit/releases/latest"
        );
    }

    // Only a strictly newer release is an update. A lower tag, and a tag with no version
    // to order at all, stay installable but are never reported as one waiting —
    // otherwise a build made after the last release nags about downgrading forever.
    #[test]
    fn only_a_newer_release_counts_as_an_update() {
        assert_eq!(step("0.29.0", "v0.30.0"), Step::Newer);
        assert_eq!(step("0.29.0", "v0.29.1"), Step::Newer);
        assert_eq!(step("0.29.0", "v1.0.0"), Step::Newer);
        assert_eq!(step("0.29.0", "v0.29.0"), Step::Same);
        assert_eq!(step("0.29.0", "0.29.0"), Step::Same);
        // ordered, not string-compared, so a differently written same version agrees
        assert_eq!(step("0.29.0", "v0.29.00"), Step::Same);
        assert_eq!(step("0.29.0", "nightly"), Step::Other);
        assert_eq!(step("nightly", "nightly"), Step::Same);
        // a version-bumped build looking at the last published tag: not an update
        assert_eq!(step("0.30.0", "v0.29.0"), Step::Other);
        assert_eq!(step("0.29.0", "v0.28.9"), Step::Other);
        // numeric fields, not string order: 0.9.0 -> 0.10.0 is forward
        assert_eq!(step("0.9.0", "v0.10.0"), Step::Newer);
        assert_eq!(step("0.10.0", "v0.9.0"), Step::Other);
        // nothing to order against
        assert_eq!(step("0.29.0", "nightly"), Step::Other);
        assert_eq!(step("0.29.0", "v0.30.0-rc1"), Step::Other);
    }

    // The sidecar is `sha256sum` output: pick the line for our asset, and refuse
    // anything that is not a sha256 rather than comparing against junk.
    #[test]
    fn digest_comes_from_the_asset_line() {
        let sum = "45c51f7d53eb22416c49c79a5dcccf94b9e0e110ba88b3ee7bbe22f98d0cd31d";
        let want = parse_sha256(sum).unwrap();
        assert_eq!(parse_digest(&format!("{sum}  vk\n"), "vk").unwrap(), want);
        // binary-mode marker, and a multi-file sidecar: the right line still wins
        let many = format!("0{}  vk-agent\n{sum} *vk\n", &sum[1..]);
        assert_eq!(parse_digest(&many, "vk").unwrap(), want);
        // `vk-agent` must not satisfy a request for `vk`, and neither must a name that
        // only differs from it by more of the marker we strip
        assert!(parse_digest(&format!("{sum}  vk-agent\n"), "vk").is_err());
        assert!(parse_digest(&format!("{sum} **vk\n"), "vk").is_err());
        assert!(parse_digest("not-a-hash  vk\n", "vk").is_err());
        assert!(parse_digest("", "vk").is_err());
        // 64 hex digits and nothing else, decoded with leading zero bytes kept
        assert!(parse_sha256(&sum[..63]).is_none());
        assert!(parse_sha256(&format!("{sum}0")).is_none());
        assert_eq!(parse_sha256(&"00".repeat(32)).unwrap(), [0u8; 32]);
        assert_eq!(parse_sha256(&"0f".repeat(32)).unwrap(), [0x0f; 32]);
    }

    // Both assets must be present; the error names what the release does carry.
    #[test]
    fn asset_pick_reports_what_is_there() {
        let assets = vec![
            ApiAsset {
                name: "vk".to_string(),
                browser_download_url: "https://example/vk".to_string(),
                size: 42,
            },
            ApiAsset {
                name: "vmlinux".to_string(),
                browser_download_url: "https://example/vmlinux".to_string(),
                size: 7,
            },
        ];
        assert_eq!(pick(&assets, "vk").unwrap().size, 42);
        let err = pick(&assets, "vk.sha256").err().unwrap().to_string();
        assert!(
            err.contains("no vk.sha256 asset") && err.contains("vmlinux"),
            "{err}"
        );
    }

    /// A stand-in for a release's binary: a script, so the smoke test can really run it.
    /// Its sha256 is hardcoded below rather than computed, so these tests pin the bytes
    /// the verify path has to arrive at instead of agreeing with themselves.
    const FAKE_VK: &str = "#!/bin/sh\necho \"vk 0.30.0 (test)\"\n";
    /// sha256 of [`FAKE_VK`]. Its first byte is zero, so a decode that drops a leading
    /// zero byte fails these tests instead of passing them.
    const FAKE_SUM: &str = "00252a75589c39789f64cc0d8ef5019eb9a991e14da2c09c2374488b711036c8";
    /// The same shape, reporting a version the release does not claim: the payload for
    /// the case where the digest gate passes and the smoke test must not.
    const WRONG_VK: &str = "#!/bin/sh\necho \"vk 0.1.0 (test)\"\n";
    const WRONG_SUM: &str = "036afa9f714743da7f15f9374e97046a0320149b7e58e516b21a1b73248ba560";
    /// The only tag the fake release server knows about.
    const FAKE_TAG: &str = "v0.30.0";

    /// How the fake release server should misbehave, so each gate is exercised against
    /// the real code path rather than a stub. Which one is in play is the first segment
    /// of the URL, so every case shares one server.
    #[derive(Clone, Copy, PartialEq)]
    enum Fault {
        None,
        /// an asset body that is not what the sidecar promises
        WrongBody,
        /// more bytes than the release announced
        Oversized,
        /// a body that matches its sidecar but is not the version asked for
        WrongVersion,
        /// the asset request fails
        AssetError,
        /// the sidecar request fails
        SidecarError,
        /// the sidecar is far too big to be one `sha256sum` line
        HugeSidecar,
        /// the API is out of quota
        RateLimited,
    }

    impl Fault {
        fn segment(self) -> &'static str {
            match self {
                Fault::None => "ok",
                Fault::WrongBody => "wrong-body",
                Fault::Oversized => "oversized",
                Fault::WrongVersion => "wrong-version",
                Fault::AssetError => "asset-error",
                Fault::SidecarError => "sidecar-error",
                Fault::HugeSidecar => "huge-sidecar",
                Fault::RateLimited => "rate-limited",
            }
        }

        fn from_segment(s: &str) -> Option<Fault> {
            Some(match s {
                "ok" => Fault::None,
                "wrong-body" => Fault::WrongBody,
                "oversized" => Fault::Oversized,
                "wrong-version" => Fault::WrongVersion,
                "asset-error" => Fault::AssetError,
                "sidecar-error" => Fault::SidecarError,
                "huge-sidecar" => Fault::HugeSidecar,
                "rate-limited" => Fault::RateLimited,
                _ => return None,
            })
        }
    }

    /// The asset body the server serves, and the length the release announces for it.
    /// The two agree except under `Oversized`, where the point is that they must not
    /// and the download has to stop at the announced length.
    fn body_of(fault: Fault) -> (Vec<u8>, u64) {
        match fault {
            Fault::WrongBody => (b"not the published bytes".to_vec(), FAKE_VK.len() as u64),
            Fault::Oversized => (FAKE_VK.repeat(4).into_bytes(), FAKE_VK.len() as u64),
            Fault::WrongVersion => (WRONG_VK.as_bytes().to_vec(), WRONG_VK.len() as u64),
            _ => (FAKE_VK.as_bytes().to_vec(), FAKE_VK.len() as u64),
        }
    }

    fn reply(code: u16, body: Vec<u8>) -> Response<Full<Bytes>> {
        Response::builder()
            .status(code)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// Serve GitHub's release API and the assets of both tools, for the one tag we
    /// publish, under `/<fault>/…` so a single server covers every case.
    fn serve(addr: SocketAddr, path: &str, user_agent: &str) -> Response<Full<Bytes>> {
        let not_found = || reply(404, br#"{"message":"Not Found"}"#.to_vec());
        let Some((seg, rest)) = path.trim_start_matches('/').split_once('/') else {
            return not_found();
        };
        let Some(fault) = Fault::from_segment(seg) else {
            return not_found();
        };
        // Echoed back rather than recorded, so the assertion needs no state shared with
        // the tests running against this one server at the same time.
        if rest == "user-agent" {
            return reply(200, user_agent.as_bytes().to_vec());
        }
        let (body, size) = body_of(fault);
        // Both tools share one stand-in body, so a single sidecar with a line for each
        // covers them both. A release publishes one single-line sidecar per binary;
        // `parse_digest` picks its own line either way.
        let sidecar = |sum: &str| format!("{sum}  {}\n{sum}  {}\n", VK.name, REGISTRY.name);
        let latest = format!("repos/{REPO}/releases/latest");
        let tagged = format!("repos/{REPO}/releases/tags/{FAKE_TAG}");
        if rest == latest || rest == tagged {
            if fault == Fault::RateLimited {
                return Response::builder()
                    .status(403)
                    .header("x-ratelimit-remaining", "0")
                    .body(Full::new(Bytes::from_static(b"rate limit exceeded")))
                    .unwrap();
            }
            let sidecar_size = sidecar(FAKE_SUM).len();
            let asset = |name: &str| {
                format!(
                    r#"{{"name":"{name}","browser_download_url":"http://{addr}/{seg}/{name}","size":{size}}},
                       {{"name":"{name}.sha256","browser_download_url":"http://{addr}/{seg}/{name}.sha256","size":{sidecar_size}}}"#
                )
            };
            let json = format!(
                r#"{{"tag_name":"{FAKE_TAG}","assets":[{},{}]}}"#,
                asset(VK.name),
                asset(REGISTRY.name)
            );
            return reply(200, json.into_bytes());
        }
        match rest.strip_suffix(".sha256") {
            // A sidecar for a tool this release does not carry is missing whichever fault is
            // in play, so the arms below never answer for an asset that is not there.
            Some(name) if name != VK.name && name != REGISTRY.name => not_found(),
            Some(_) if fault == Fault::SidecarError => reply(500, b"boom".to_vec()),
            Some(_) if fault == Fault::HugeSidecar => {
                reply(200, sidecar(FAKE_SUM).repeat(4096).into_bytes())
            }
            Some(_) if fault == Fault::WrongVersion => reply(200, sidecar(WRONG_SUM).into_bytes()),
            Some(_) => reply(200, sidecar(FAKE_SUM).into_bytes()),
            None if rest == VK.name || rest == REGISTRY.name => {
                if fault == Fault::AssetError {
                    reply(500, b"boom".to_vec())
                } else {
                    reply(200, body)
                }
            }
            _ => not_found(),
        }
    }

    /// The API root to hand `resolve` for a given fault, starting the one fake release
    /// server on first use. Its own thread + current-thread runtime, like vk-driver's
    /// fake `regproxy` upstream, so the accept loop never competes with a test's runtime
    /// threads.
    fn release_api(fault: Fault) -> String {
        static ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
        let addr = ADDR.get_or_init(|| {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    loop {
                        let Ok((stream, _)) = listener.accept().await else {
                            break;
                        };
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let svc = service_fn(move |req: Request<Incoming>| async move {
                                let ua = req
                                    .headers()
                                    .get(hyper::header::USER_AGENT)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or_default()
                                    .to_owned();
                                Ok::<_, Infallible>(serve(addr, req.uri().path(), &ua))
                            });
                            let _ = http1::Builder::new().serve_connection(io, svc).await;
                        });
                    }
                });
            });
            addr
        });
        format!("http://{addr}/{}", fault.segment())
    }

    /// The very client the entry points use, so its configuration is on the tested path.
    fn test_client() -> reqwest::Client {
        // reqwest (rustls-no-provider) needs a crypto provider before a client builds;
        // each binary's `main` installs it for real runs.
        let _ = rustls::crypto::ring::default_provider().install_default();
        VK.http_client().unwrap()
    }

    /// A scratch directory holding a stand-in for the installed binary at `mode`, removed
    /// however the test ends — a failed assertion must not leak it.
    ///
    /// Beside the test binary itself (so, under `target/`) rather than in `/tmp`: the smoke
    /// test execs the download from this directory, and a host that mounts `/tmp` `noexec`
    /// would fail every test here for a reason that has nothing to do with the code. Not
    /// `OUT_DIR` as the pre-extraction module used, since this crate has no build script
    /// to set it.
    struct Scratch {
        dir: PathBuf,
        exe: PathBuf,
    }

    impl Scratch {
        /// Named after the tool, the test and the pid, so two suites on the same host never
        /// share a path and pull each other's tree out mid-run. Removed first all the same,
        /// so a recycled pid starts clean instead of on an older run's leftovers.
        fn new(tool: &Tool, name: &str, mode: u32) -> Scratch {
            let here = std::env::current_exe().unwrap();
            let dir = here.parent().unwrap().join(format!(
                "selfupdate-{}-{name}-{}",
                tool.name,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let exe = dir.join(tool.name);
            fs::write(&exe, b"the binary being replaced").unwrap();
            fs::set_permissions(&exe, fs::Permissions::from_mode(mode)).unwrap();
            Scratch { dir, exe }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // Restore traversal first: `a_rename_that_fails…` locks a subdirectory down.
            for e in fs::read_dir(&self.dir).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    let _ = fs::set_permissions(e.path(), fs::Permissions::from_mode(0o700));
                }
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// The temp downloads `tool` left behind in `dir`, which must always be none.
    fn leftovers(tool: &Tool, dir: &Path) -> Vec<String> {
        let prefix = format!(".{}-update.", tool.name);
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&prefix))
            .collect()
    }

    /// The smoke test execs a file this process just wrote, so it races every `fork` the
    /// process makes: one landing while the download is still open inherits the write fd and
    /// holds the file busy past the close, until that child execs. A write fd of our own
    /// stands in for that inherited one — released while the smoke test is already looking
    /// again, and the download is good, so the verdict must be that it passes.
    #[test]
    fn the_smoke_test_waits_out_a_binary_something_still_holds_open() {
        let s = Scratch::new(&VK, "busy", 0o755);
        fs::write(&s.exe, FAKE_VK).unwrap();

        let held = OpenOptions::new().write(true).open(&s.exe).unwrap();
        // Released a long way inside the 180ms budget, and late enough that the first look
        // is the one that finds the file busy.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(held);
        });
        let looking = std::time::Instant::now();
        VK.smoke_test(&s.exe, "0.30.0").unwrap();
        assert!(
            looking.elapsed() >= Duration::from_millis(20),
            "the first look succeeded: nothing waited"
        );

        // Held for good: the wait is a budget, not a spin, so a file that never frees up
        // still reports the errno it failed on.
        let _held = OpenOptions::new().write(true).open(&s.exe).unwrap();
        let err = VK.smoke_test(&s.exe, "0.30.0").unwrap_err();
        assert_eq!(
            err.downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error()),
            Some(libc::ETXTBSY),
            "{err:#}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn install_publishes_a_download_that_passes_both_gates() {
        let client = test_client();
        let target = VK
            .resolve(&client, &release_api(Fault::None), None)
            .await
            .unwrap();
        assert_eq!(target.tag, FAKE_TAG);
        assert_eq!(target.size, FAKE_VK.len() as u64);

        // 0750 rather than the 0755 default: an install deliberately narrowed keeps its
        // mode instead of being widened, and the umask does not get to decide it either.
        let s = Scratch::new(&VK, "ok", 0o750);
        VK.install(&client, &target, &s.exe, &s.dir).await.unwrap();
        assert_eq!(fs::read_to_string(&s.exe).unwrap(), FAKE_VK);
        assert_eq!(
            fs::metadata(&s.exe).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        assert_eq!(leftovers(&VK, &s.dir), Vec::<String>::new());
    }

    // Which asset of a release an update installs, which digest line it is checked
    // against, and what the download is called on the way in all come from the tool —
    // so a second tool in the same release installs its own binary, not `vk`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_tool_installs_its_own_asset() {
        let client = test_client();
        let target = REGISTRY
            .resolve(&client, &release_api(Fault::None), None)
            .await
            .unwrap();
        assert!(target.url.ends_with("/vk-registry"), "{}", target.url);
        assert!(
            target.digest_url.ends_with("/vk-registry.sha256"),
            "{}",
            target.digest_url
        );
        assert_eq!(
            REGISTRY.tmp_name(),
            format!(".vk-registry-update.{}", std::process::id())
        );

        let s = Scratch::new(&REGISTRY, "ok", 0o755);
        REGISTRY
            .install(&client, &target, &s.exe, &s.dir)
            .await
            .unwrap();
        assert_eq!(fs::read_to_string(&s.exe).unwrap(), FAKE_VK);
        assert_eq!(leftovers(&REGISTRY, &s.dir), Vec::<String>::new());

        // and a release that does not carry it at all is named as such, rather than
        // falling back to another tool's asset
        let err = format!(
            "{:#}",
            Tool {
                name: "vk-agent",
                version: "0.30.0"
            }
            .resolve(&client, &release_api(Fault::None), None)
            .await
            .expect_err("not in this release")
        );
        assert!(err.contains("no vk-agent asset"), "{err}");
    }

    // GitHub answers nothing without a `User-Agent`, and it is built from the tool too, so
    // each binary identifies itself instead of every update looking like a `vk` one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_tool_identifies_itself_to_the_api() {
        // `test_client` installs the crypto provider a client needs to build, so it has to
        // come before the second tool's.
        let vk_client = test_client();
        let clients = [(VK, vk_client), (REGISTRY, REGISTRY.http_client().unwrap())];
        let api = release_api(Fault::None);
        for (tool, client) in clients {
            let seen = client
                .get(format!("{api}/user-agent"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert_eq!(seen, format!("{}/{}", tool.name, tool.version));
        }
    }

    // The point of the whole crate: a download that fails either gate never becomes the
    // installed binary, and nothing unverified is left next to it. One directory for all
    // of the cases, so a failure to clean up surfaces as the next one refusing to create
    // its temp file.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_download_that_fails_a_gate_never_becomes_the_binary() {
        let client = test_client();
        let s = Scratch::new(&VK, "gates", 0o755);
        let before = fs::read(&s.exe).unwrap();
        for (fault, want) in [
            (Fault::WrongBody, "does not match the published digest"),
            (Fault::Oversized, "longer than the"),
            (Fault::WrongVersion, "did not report version 0.30.0"),
            (Fault::AssetError, "500"),
            (Fault::SidecarError, "500"),
            (Fault::HugeSidecar, "is larger than"),
        ] {
            let target = VK
                .resolve(&client, &release_api(fault), None)
                .await
                .unwrap();
            let err = format!(
                "{:#}",
                VK.install(&client, &target, &s.exe, &s.dir)
                    .await
                    .expect_err("a failed gate must not install")
            );
            assert!(err.contains(want), "expected {want:?}, got {err:?}");
            assert_eq!(
                fs::read(&s.exe).unwrap(),
                before,
                "{want}: exe was replaced"
            );
            assert_eq!(
                leftovers(&VK, &s.dir),
                Vec::<String>::new(),
                "{want}: left a temp"
            );
        }
    }

    // The binary being replaced has to still be there. `current_exe` hands back a
    // `…/vk (deleted)` pathname once it is not, and renaming onto that would report
    // success while installing something nobody runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn install_refuses_when_the_binary_it_would_replace_is_gone() {
        let client = test_client();
        let target = VK
            .resolve(&client, &release_api(Fault::None), None)
            .await
            .unwrap();
        let s = Scratch::new(&VK, "gone", 0o755);
        fs::remove_file(&s.exe).unwrap();
        let err = format!(
            "{:#}",
            VK.install(&client, &target, &s.exe, &s.dir)
                .await
                .expect_err("nothing to replace")
        );
        assert!(err.contains("is gone"), "{err}");
        // refused before anything was downloaded, so there is nothing to clean up
        assert_eq!(leftovers(&VK, &s.dir), Vec::<String>::new());
    }

    // The other half of the cleanup guarantee: a verified download whose rename cannot
    // happen is removed too, rather than left executable beside the binary. `exe` sits in
    // a directory of its own, made unwritable after it is populated, so the download
    // lands in `dir` as usual and only the rename is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rename_that_cannot_happen_leaves_no_temp_behind() {
        // Root ignores the directory mode, so there would be no failure to observe.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let client = test_client();
        let target = VK
            .resolve(&client, &release_api(Fault::None), None)
            .await
            .unwrap();
        let s = Scratch::new(&VK, "rename", 0o755);
        let locked = s.dir.join("locked");
        fs::create_dir(&locked).unwrap();
        let exe = locked.join("vk");
        fs::write(&exe, b"the binary being replaced").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();

        let err = format!(
            "{:#}",
            VK.install(&client, &target, &exe, &s.dir)
                .await
                .expect_err("the rename must fail")
        );
        assert!(err.contains("installing"), "{err}");
        assert_eq!(leftovers(&VK, &s.dir), Vec::<String>::new());
    }

    // A temp file already at the path is someone else's: refuse it, and — since the error
    // tells the user to remove it — leave it there to be removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_leftover_temp_is_reported_and_not_touched() {
        let client = test_client();
        let target = VK
            .resolve(&client, &release_api(Fault::None), None)
            .await
            .unwrap();
        let s = Scratch::new(&VK, "leftover", 0o755);
        let tmp = s.dir.join(VK.tmp_name());
        fs::write(&tmp, b"a previous run's").unwrap();

        let err = format!(
            "{:#}",
            VK.install(&client, &target, &s.exe, &s.dir)
                .await
                .expect_err("must not reuse it")
        );
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(fs::read(&tmp).unwrap(), b"a previous run's");
    }

    // The mode is copied from the binary being replaced, minus the bits that must not
    // follow bytes off the network.
    #[test]
    fn the_install_mode_comes_from_the_binary_being_replaced() {
        let s = Scratch::new(&VK, "mode", 0o4751);
        assert_eq!(
            mode_of(&s.exe),
            0o751,
            "set-user-ID must not be carried over"
        );
        // whatever it copies, the result has to be something the smoke test can run
        fs::set_permissions(&s.exe, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&s.exe), 0o744);
        assert_eq!(mode_of(&s.dir.join("absent")), INSTALL_MODE);
    }

    // A tag that was never released and an exhausted API quota are different problems:
    // reporting the second as the first sends the user hunting a typo.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_separates_a_missing_release_from_a_rate_limit() {
        let client = test_client();

        let err = format!(
            "{:#}",
            VK.resolve(&client, &release_api(Fault::None), Some("0.28.0"))
                .await
                .expect_err("no such tag")
        );
        assert!(err.contains("no release v0.28.0"), "{err}");

        let err = format!(
            "{:#}",
            VK.resolve(&client, &release_api(Fault::RateLimited), None)
                .await
                .expect_err("out of quota")
        );
        assert!(err.contains("rate limit is exhausted"), "{err}");
    }
}
