//! `vk toolchain`: the virtkit release a project pins, and the artifacts of it this host
//! has.
//!
//! `[requires] min-version` is a compatibility floor — the oldest `vk` that can run the
//! project at all. This is the other half: the exact release the team builds against,
//! recorded in `.virtkit/toolchain.lock` beside the config and tracked with it, so a
//! developer's laptop, a Docker image build and a CI runner all use the same bytes. The
//! lock names, per artifact and platform, the digest and where to fetch it from; nothing
//! here trusts a URL, only the digest the lock already carries, which is what makes a
//! mirror as safe as GitHub.
//!
//! Installing means filling a versioned cache under the user's cache directory. It never
//! touches the `vk` on PATH: a project pinning an older release must not silently
//! downgrade the tool the user installed for everything else. `export` then hands the
//! cached paths and digests to whatever consumes them — the shell, a Dockerfile's build
//! args, a CI image builder — so nothing else has to parse the lock.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dev::config::LOCK_FILE;

/// The artifacts a lock covers when the user names none: everything a release publishes
/// that a project can consume. A release that publishes only some of them locks those —
/// only a name the user typed has to be there.
///
/// `.github/workflows/release.yml` publishes exactly this list, and `quality.yml` checks
/// that the two still agree.
const DEFAULT_ARTIFACTS: [&str; 5] = ["vk", "vk-agent", "vk-registry", "vk-runnerctl", "vmlinux"];

/// Written above the lock's TOML: it is a tracked file people will open, and the first
/// question on opening it is what wrote it and what may edit it.
const HEADER: &str = "\
# .virtkit/toolchain.lock — the virtkit release this project builds against.
#
# Written by `vk toolchain lock`, read by `vk toolchain install|export|status` and by
# virtkit's install.sh. Track it in git; change it with `vk toolchain lock --version X`
# rather than by hand.
";

/// `.virtkit/toolchain.lock`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    /// the release, without the tag's `v`
    version: String,
    /// artifact name -> platform -> where to get it and what it must hash to
    artifacts: BTreeMap<String, BTreeMap<String, Entry>>,
}

/// One artifact on one platform.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    sha256: String,
    /// where to fetch it, in the order to try: the release itself, then the mirrors the
    /// lock was written with.
    urls: Vec<String>,
}

/// What `vk toolchain export` prints.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
pub(crate) enum Format {
    /// `NAME='value'` lines, for `eval "$(vk toolchain export)"`
    Shell,
    /// one JSON object: the version and each artifact's path and digest
    Json,
}

/// The platform key a lock's entries are stored under: `linux-x86_64` here. Releases are
/// built for one platform today, but the lock is a file other hosts read, so what an entry
/// applies to is written down rather than assumed.
fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

// ---------------------------------------------------------------------------
// The lock file

/// Find the lock a caller in `from` works with: `.virtkit/toolchain.lock` there or in an
/// ancestor, no further up than the checkout root — the same walk the dev config gets.
fn find_lock(from: &Path) -> Option<PathBuf> {
    let stop = crate::dev::config::worktree_root(from);
    for dir in from.ancestors() {
        let candidate = dir.join(LOCK_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        if stop.as_deref() == Some(dir) {
            break;
        }
    }
    None
}

/// The lock to read: the one named, else the one found from the current directory.
pub(crate) fn lock_to_read(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let from = std::env::current_dir().context("resolving the current directory")?;
    find_lock(&from).with_context(|| {
        format!(
            "no {LOCK_FILE} in {} or above it — `vk toolchain lock` writes one, --lock names \
             the file",
            from.display()
        )
    })
}

/// The lock to write: the one named, else the one already in this checkout, else a new one
/// at the checkout root (the current directory outside a checkout).
pub(crate) fn lock_to_write(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let from = std::env::current_dir().context("resolving the current directory")?;
    if let Some(found) = find_lock(&from) {
        return Ok(found);
    }
    let root = crate::dev::config::worktree_root(&from).unwrap_or(from);
    Ok(root.join(LOCK_FILE))
}

/// A name the cache can be asked to hold: the version and the artifact names become path
/// components under the cache root, and a lock is a tracked file a checkout hands us.
/// Anything but a plain name — a separator, a `..`, an empty string — would let the file
/// steer an install outside the cache and write attacker-chosen bytes at mode 0755.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn read_lock(path: &Path) -> Result<Lock> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if !is_plain_name(&lock.version) {
        bail!(
            "{} pins {:?}, which is not a version",
            path.display(),
            lock.version
        );
    }
    for (name, per_platform) in &lock.artifacts {
        if !is_plain_name(name) {
            bail!(
                "{} names an artifact {name:?}, which is not an artifact name",
                path.display()
            );
        }
        for (platform, entry) in per_platform {
            // An entry with nowhere to fetch from would leave `install` reporting success
            // with the artifact absent.
            if entry.urls.is_empty() {
                bail!(
                    "{} gives {name} on {platform} no url to fetch it from",
                    path.display()
                );
            }
        }
    }
    Ok(lock)
}

/// Render a lock as the file's own text, header included.
fn render(lock: &Lock) -> Result<String> {
    let body = toml::to_string_pretty(lock).context("serializing the lock")?;
    Ok(format!("{HEADER}\n{body}"))
}

/// Write `lock` to `path`, atomically: a half-written lock is a project nobody can build.
fn write_lock(lock: &Lock, path: &Path) -> Result<()> {
    let text = render(lock)?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    // A dotfile beside the lock, named after this process and refused if it is already
    // there: two `vk toolchain lock` runs never write through each other's file, and a
    // crash leaves a name no later run mistakes for its own.
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let outcome = f
        .write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .with_context(|| format!("writing {}", tmp.display()))
        // The rename and the directory fsync `vk update` publishes a binary with: a lock
        // that is tracked in git must not survive a host crash as an empty name.
        .and_then(|()| vk_selfupdate::publish(&tmp, path, &dir));
    if outcome.is_err() {
        // Best-effort: an unpublished lock must not be left lying beside the real one, but
        // the original error is what the caller needs to see.
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}

/// The lock a release resolves to: the release's own URL first, then each mirror, which is
/// the order [`install`] tries them in.
fn build_lock(
    version: &str,
    platform: &str,
    resolved: &[vk_selfupdate::Artifact],
    mirrors: &[String],
) -> Lock {
    let mut artifacts: BTreeMap<String, BTreeMap<String, Entry>> = BTreeMap::new();
    for a in resolved {
        let mut urls = vec![a.url.clone()];
        urls.extend(
            mirrors
                .iter()
                .map(|m| format!("{}/v{version}/{}", m.trim_end_matches('/'), a.name)),
        );
        artifacts.entry(a.name.clone()).or_default().insert(
            platform.to_string(),
            Entry {
                sha256: a.sha256.clone(),
                urls,
            },
        );
    }
    Lock {
        version: version.to_string(),
        artifacts,
    }
}

/// `vk toolchain lock`: resolve a release and record what this project builds against.
pub(crate) async fn lock(
    version: Option<&str>,
    mirrors: &[String],
    artifacts: &[String],
    path: &Path,
) -> Result<()> {
    let named = !artifacts.is_empty();
    let names: Vec<&str> = match named {
        false => DEFAULT_ARTIFACTS.to_vec(),
        true => artifacts.iter().map(String::as_str).collect(),
    };
    let client = vk_selfupdate::toolchain_client()?;
    let resolved = vk_selfupdate::artifacts(&client, version, &names).await?;
    let version = resolved.version;
    if !resolved.missing.is_empty() {
        let missing = resolved.missing.join(", ");
        // A name the user typed is a mistake to report; the default set is whatever the
        // release ships, so what it does not ship is a note and the rest is locked.
        if named {
            bail!("release {version} publishes no {missing}");
        }
        eprintln!("note: release {version} publishes no {missing} — not locked");
    }
    if resolved.artifacts.is_empty() {
        bail!("release {version} publishes none of {}", names.join(", "));
    }
    let platform = platform();
    let lock = build_lock(&version, &platform, &resolved.artifacts, mirrors);
    write_lock(&lock, path)?;
    println!("{} pins virtkit {version} ({platform})", path.display());
    for (name, entry) in lock
        .artifacts
        .iter()
        .filter_map(|(n, p)| Some((n, p.get(&platform)?)))
    {
        println!("  {name:<14} {}", entry.sha256);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The cache

/// Where installed artifacts live: `$VIRTKIT_TOOLCHAIN_CACHE`, else
/// `$XDG_CACHE_HOME/virtkit/toolchain`, else `~/.cache/virtkit/toolchain`. Versioned one
/// level down, so two projects on different releases do not fight over one directory.
fn cache_root() -> Result<PathBuf> {
    cache_root_from(
        std::env::var_os("VIRTKIT_TOOLCHAIN_CACHE"),
        std::env::var_os("XDG_CACHE_HOME"),
        std::env::var_os("HOME"),
    )
}

fn cache_root_from(
    override_dir: Option<OsString>,
    xdg: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf> {
    if let Some(dir) = override_dir.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = xdg.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir).join("virtkit/toolchain"));
    }
    let home = home.filter(|v| !v.is_empty()).context(
        "neither VIRTKIT_TOOLCHAIN_CACHE, XDG_CACHE_HOME nor HOME is set, so there is \
         nowhere to cache the toolchain",
    )?;
    Ok(PathBuf::from(home).join(".cache/virtkit/toolchain"))
}

/// The mode an artifact is published with: the binaries are meant to be run, the kernel is
/// meant to be read.
fn mode_of(name: &str) -> u32 {
    match name {
        "vmlinux" => 0o644,
        _ => 0o755,
    }
}

/// The sha256 of the file at `path`, streamed rather than read whole — `vmlinux` and the
/// binaries are tens of megabytes each.
fn digest_of(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or_default());
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Whether the cache already holds this artifact: the file is there *and* hashes to the
/// digest the lock records. Re-hashed rather than trusted for being there — the cache is an
/// ordinary user directory, and an interrupted fetch or an edited file must not be handed
/// to a build as the locked artifact. Unreadable counts as not installed, not as an error:
/// it is a file to replace.
fn is_installed(path: &Path, sha256: &str) -> bool {
    path.is_file() && digest_of(path).is_ok_and(|d| d == sha256)
}

/// What an install has to do for one artifact.
#[derive(Debug, PartialEq)]
enum Step {
    /// already in the cache, hashing to what the lock says
    Cached,
    /// not there, or there with the wrong contents
    Fetch { sha256: String, urls: Vec<String> },
}

#[derive(Debug, PartialEq)]
struct Planned {
    name: String,
    path: PathBuf,
    step: Step,
}

/// What `install` would do, without doing any of it: which artifacts of this platform the
/// lock covers, where each one goes, and whether the cache already has it.
///
/// A lock covering nothing for this platform is an error rather than an empty plan: an
/// install that says nothing and exits 0 is the worst answer.
fn plan_install(
    lock: &Lock,
    dir: &Path,
    platform: &str,
    filter: &[String],
) -> Result<Vec<Planned>> {
    for name in filter {
        if !lock.artifacts.contains_key(name) {
            bail!(
                "the lock has no {name} artifact (it has: {})",
                lock.artifacts
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    let mut out = Vec::new();
    for (name, per_platform) in &lock.artifacts {
        if !filter.is_empty() && !filter.iter().any(|f| f == name) {
            continue;
        }
        let Some(entry) = per_platform.get(platform) else {
            // Reached only for a name that passed the filter above, so an empty filter is
            // "every artifact" and this one is simply not for us.
            if filter.is_empty() {
                continue;
            }
            bail!("the lock has no {name} for {platform}");
        };
        let path = dir.join(name);
        let cached = is_installed(&path, &entry.sha256);
        out.push(Planned {
            name: name.clone(),
            path,
            step: match cached {
                true => Step::Cached,
                false => Step::Fetch {
                    sha256: entry.sha256.clone(),
                    urls: entry.urls.clone(),
                },
            },
        });
    }
    if out.is_empty() {
        let covered: Vec<&str> = lock
            .artifacts
            .values()
            .flat_map(|p| p.keys())
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        bail!(
            "the lock has nothing for {platform} (it covers: {})",
            covered.join(", ")
        );
    }
    Ok(out)
}

/// How an install gets an artifact's bytes. Downloading is the only part of an install that
/// needs the network, so it is the only part the tests replace.
trait Fetch {
    async fn fetch(&self, url: &str, sha256: &str, dest: &Path, mode: u32) -> Result<()>;
}

/// The real one: a digest-verified download, published atomically. One client for the
/// whole install, so five artifacts off the same host are one connection and not five.
struct Download(reqwest::Client);

impl Fetch for Download {
    async fn fetch(&self, url: &str, sha256: &str, dest: &Path, mode: u32) -> Result<()> {
        vk_selfupdate::fetch(&self.0, url, sha256, dest, mode).await
    }
}

/// `vk toolchain install`: put the locked artifacts of this platform in the cache.
pub(crate) async fn install(path: &Path, filter: &[String], offline: bool) -> Result<()> {
    let lock = read_lock(path)?;
    let dir = cache_root()?.join(&lock.version);
    let plan = plan_install(&lock, &dir, &platform(), filter)?;
    // Built even for an offline run: it costs nothing and keeps the two paths one.
    let how = Download(vk_selfupdate::toolchain_client()?);
    run_install(&plan, &dir, offline, &how).await
}

async fn run_install(plan: &[Planned], dir: &Path, offline: bool, how: &impl Fetch) -> Result<()> {
    if plan.iter().any(|p| p.step != Step::Cached) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    for item in plan {
        let Step::Fetch { sha256, urls } = &item.step else {
            println!("{:<14} cached {}", item.name, item.path.display());
            continue;
        };
        if offline {
            bail!(
                "{} is not in the cache ({}) and --offline forbids fetching it",
                item.name,
                item.path.display()
            );
        }
        // Every URL serves the same locked digest, so a mirror is only ever another route
        // to the same bytes; the first that delivers them wins.
        let mut failures = Vec::new();
        for url in urls {
            match how
                .fetch(url, sha256, &item.path, mode_of(&item.name))
                .await
            {
                Ok(()) => {
                    println!("{:<14} {} <- {url}", item.name, item.path.display());
                    failures.clear();
                    break;
                }
                Err(e) => failures.push(format!("{url}: {e:#}")),
            }
        }
        if !failures.is_empty() {
            bail!("cannot fetch {}:\n  {}", item.name, failures.join("\n  "));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reporting: export and status

/// The environment variable an artifact's path is exported as: `vk-agent` ->
/// `VIRTKIT_VK_AGENT`, with `_SHA256` beside it for the digest.
fn var_of(name: &str) -> String {
    format!("VIRTKIT_{}", name.to_uppercase().replace('-', "_"))
}

/// `NAME`/`value` pairs for the lock: the version, then each artifact's cached path (empty
/// when it is not installed) and locked digest.
fn export_vars(
    lock: &Lock,
    dir: &Path,
    platform: &str,
    installed: &dyn Fn(&Path, &str) -> bool,
) -> Vec<(String, String)> {
    let mut out = vec![("VIRTKIT_VERSION".to_string(), lock.version.clone())];
    for (name, per_platform) in &lock.artifacts {
        let Some(entry) = per_platform.get(platform) else {
            continue;
        };
        let path = dir.join(name);
        let var = var_of(name);
        out.push((
            var.clone(),
            match installed(&path, &entry.sha256) {
                true => path.display().to_string(),
                false => String::new(),
            },
        ));
        out.push((format!("{var}_SHA256"), entry.sha256.clone()));
    }
    out
}

/// `vk toolchain export`: the lock, in a form a script consumes without parsing TOML.
pub(crate) fn export(path: &Path, format: Format) -> Result<()> {
    let lock = read_lock(path)?;
    let dir = cache_root()?.join(&lock.version);
    // The same test `status` reports, so a cache entry that no longer matches is never
    // exported as a usable path with the locked digest beside it.
    let vars = export_vars(&lock, &dir, &platform(), &is_installed);
    print!("{}", render_export(&vars, format));
    Ok(())
}

fn render_export(vars: &[(String, String)], format: Format) -> String {
    let mut out = String::new();
    match format {
        // No `export`: this is meant to be `eval`d or sourced into the shell that then uses
        // the values, and a script that wants them in a child's environment exports them
        // itself.
        Format::Shell => {
            for (name, value) in vars {
                out.push_str(&format!("{name}={}\n", crate::shell::quote(value)));
            }
        }
        Format::Json => {
            let map: serde_json::Map<String, serde_json::Value> = vars
                .iter()
                .map(|(n, v)| (n.clone(), serde_json::Value::String(v.clone())))
                .collect();
            if let Ok(text) = serde_json::to_string_pretty(&map) {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
    out
}

/// How the `vk` doing the asking relates to the release the lock pins.
fn against_lock(own: &str, locked: &str) -> &'static str {
    let parsed = |v: &str| v.parse::<crate::check::Version>().ok();
    match (parsed(own), parsed(locked)) {
        (Some(own), Some(locked)) if own == locked => "the locked release",
        (Some(own), Some(locked)) if own > locked => "newer than the lock",
        (Some(_), Some(_)) => "older than the lock",
        // A build whose version cannot be ordered (a development tree) says so rather than
        // claiming a relation it cannot work out.
        _ => "not comparable to the lock",
    }
}

/// The version a workspace's lock pins, when this `vk` is older than it — the one case
/// worth a word during `vk dev up`: a newer `vk` is a deliberate development build, and an
/// equal one is the point of the lock.
pub(crate) fn older_than_lock(workspace: &Path) -> Option<String> {
    let lock = read_lock(&find_lock(workspace)?).ok()?;
    let own: crate::check::Version = env!("CARGO_PKG_VERSION").parse().ok()?;
    let locked: crate::check::Version = lock.version.parse().ok()?;
    (own < locked).then_some(lock.version)
}

/// `vk toolchain status`: what is locked, what is installed, and which `vk` is answering.
pub(crate) fn status(path: &Path) -> Result<()> {
    let lock = read_lock(path)?;
    let platform = platform();
    let dir = cache_root()?.join(&lock.version);
    let mut out = String::new();
    // Wide enough for the longest artifact name a release publishes (`vk-runnerctl`).
    let mut line = |k: &str, v: String| out.push_str(&format!("{k:<14}{v}\n"));
    line("lock", path.display().to_string());
    line("version", format!("{} ({platform})", lock.version));
    line("cache", dir.display().to_string());
    for (name, per_platform) in &lock.artifacts {
        let Some(entry) = per_platform.get(&platform) else {
            line(name, format!("not locked for {platform}"));
            continue;
        };
        let file = dir.join(name);
        let state = match file.is_file() {
            false => "missing — `vk toolchain install` fetches it".to_string(),
            true if is_installed(&file, &entry.sha256) => format!("installed {}", file.display()),
            true => format!("{} does not match the lock", file.display()),
        };
        line(name, state);
    }
    let own = env!("CARGO_PKG_VERSION");
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vk"));
    // Not `vk`: that row is the locked artifact, and this one is the binary answering.
    line(
        "this vk",
        format!(
            "{} is {own} — {}",
            exe.display(),
            against_lock(own, &lock.version)
        ),
    );
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-toolchain-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn artifact(name: &str, sha: &str) -> vk_selfupdate::Artifact {
        vk_selfupdate::Artifact {
            name: name.to_string(),
            url: format!("https://github.com/virtkit-dev/virtkit/releases/download/v0.60.0/{name}"),
            sha256: sha.to_string(),
        }
    }

    /// Two stand-in artifacts and their real sha256s, hardcoded rather than computed so
    /// these tests pin the bytes the verify path has to arrive at.
    const BYTES_VK: &str = "#!/bin/sh\necho \"vk 0.30.0 (test)\"\n";
    const SUM_VK: &str = "00252a75589c39789f64cc0d8ef5019eb9a991e14da2c09c2374488b711036c8";
    const BYTES_AGENT: &str = "#!/bin/sh\necho \"vk 0.1.0 (test)\"\n";
    const SUM_AGENT: &str = "036afa9f714743da7f15f9374e97046a0320149b7e58e516b21a1b73248ba560";

    fn sample() -> Lock {
        build_lock(
            "0.60.0",
            "linux-x86_64",
            &[artifact("vk", SUM_VK), artifact("vk-agent", SUM_AGENT)],
            &["https://mirror.example/virtkit/".to_string()],
        )
    }

    // The release's own URL comes first and the mirrors follow in the order they were
    // given, under the version's own tag directory — the order `install` tries them in.
    #[test]
    fn mirrors_follow_the_release_url() {
        let lock = sample();
        let entry = &lock.artifacts["vk-agent"]["linux-x86_64"];
        assert_eq!(
            entry.urls,
            vec![
                "https://github.com/virtkit-dev/virtkit/releases/download/v0.60.0/vk-agent",
                // the trailing slash of the mirror is not doubled
                "https://mirror.example/virtkit/v0.60.0/vk-agent",
            ]
        );
        assert_eq!(entry.sha256, SUM_AGENT);
    }

    // What is written is what comes back, header and all — the file is tracked in the
    // project, so its text is part of the interface.
    #[test]
    fn lock_survives_a_round_trip() {
        let dir = tmpdir("round-trip");
        let path = dir.join(".virtkit/toolchain.lock");
        let lock = sample();
        write_lock(&lock, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# .virtkit/toolchain.lock"), "{text}");
        assert!(text.contains("version = \"0.60.0\""), "{text}");
        assert!(text.contains("[artifacts.vk-agent.linux-x86_64]"), "{text}");
        assert_eq!(read_lock(&path).unwrap(), lock);
        // A key virtkit does not know is an error rather than a silent omission.
        std::fs::write(&path, format!("{text}\nstrict = true\n")).unwrap();
        assert!(read_lock(&path).is_err());
        // The temp it published through is gone, and named after this process while it
        // existed — a fixed name would have two writers overwriting each other.
        let left: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert_eq!(left, Vec::<OsString>::new());
    }

    // The lock is a tracked file a checkout hands us, and its version and artifact names
    // become path components under the cache root: anything that could steer a 0755 write
    // out of the cache is refused when the file is read, before any path is built.
    #[test]
    fn a_lock_that_could_escape_the_cache_is_refused() {
        let dir = tmpdir("hostile");
        let path = dir.join("toolchain.lock");
        let write = |body: &str| std::fs::write(&path, body).unwrap();
        let entry = "sha256 = \"00\"\nurls = [\"https://example/x\"]\n";

        write(&format!(
            "version = \"../../../../tmp/pwn\"\n[artifacts.vk.linux-x86_64]\n{entry}"
        ));
        assert!(read_lock(&path).is_err(), "a traversing version");
        write(&format!(
            "version = \"0.60.0\"\n[artifacts.\"../evil\".linux-x86_64]\n{entry}"
        ));
        assert!(read_lock(&path).is_err(), "a traversing artifact name");
        write(&format!(
            "version = \"\"\n[artifacts.vk.linux-x86_64]\n{entry}"
        ));
        assert!(read_lock(&path).is_err(), "no version at all");
        // An entry with nowhere to fetch from would make `install` report success with the
        // artifact absent.
        write("version = \"0.60.0\"\n[artifacts.vk.linux-x86_64]\nsha256 = \"00\"\nurls = []\n");
        assert!(read_lock(&path).is_err(), "an entry with no url");
        // and the ordinary shapes still read
        write(&format!(
            "version = \"0.60.0\"\n[artifacts.vk-agent.linux-x86_64]\n{entry}"
        ));
        assert!(read_lock(&path).is_ok());
    }

    // Names reach the shell upper-cased with `-` as `_`, a path is empty until the artifact
    // is installed, and every value is quoted so `eval` cannot be steered by one.
    #[test]
    fn export_names_and_quotes_every_value() {
        let dir = Path::new("/cache/0.60.0");
        let lock = sample();
        let missing = export_vars(&lock, dir, "linux-x86_64", &|_, _| false);
        assert_eq!(
            missing,
            vec![
                ("VIRTKIT_VERSION".into(), "0.60.0".into()),
                ("VIRTKIT_VK".into(), String::new()),
                ("VIRTKIT_VK_SHA256".into(), SUM_VK.into()),
                ("VIRTKIT_VK_AGENT".into(), String::new()),
                ("VIRTKIT_VK_AGENT_SHA256".into(), SUM_AGENT.into()),
            ]
        );
        let installed = export_vars(&lock, dir, "linux-x86_64", &|_, _| true);
        assert_eq!(installed[3].1, "/cache/0.60.0/vk-agent");
        // The predicate is the digest check `status` reports, so a cached file that no
        // longer matches exports an empty path rather than a usable one.
        let stale = export_vars(&lock, dir, "linux-x86_64", &|_, sha| sha == SUM_VK);
        assert_eq!(stale[1].1, "/cache/0.60.0/vk");
        assert_eq!(stale[3].1, String::new());
        // Nothing is locked for another platform, so nothing is exported for one.
        assert_eq!(
            export_vars(&lock, dir, "macos-aarch64", &|_, _| true).len(),
            1
        );

        let shell = render_export(&installed, Format::Shell);
        assert!(shell.starts_with("VIRTKIT_VERSION='0.60.0'\n"), "{shell}");
        assert!(
            shell.contains("VIRTKIT_VK_AGENT='/cache/0.60.0/vk-agent'\n"),
            "{shell}"
        );
        // No `export`: the caller decides what its children see.
        assert!(!shell.contains("export "), "{shell}");
        assert_eq!(
            render_export(&[("V".into(), "a'b".into())], Format::Shell),
            "V='a'\\''b'\n"
        );
        let json = render_export(&installed, Format::Json);
        assert!(
            json.contains("\"VIRTKIT_VK_AGENT\": \"/cache/0.60.0/vk-agent\""),
            "{json}"
        );
    }

    // A cached file is the locked artifact only if it hashes to the locked digest; anything
    // else is fetched again, and `--offline` says which artifact it cannot supply.
    #[tokio::test]
    async fn install_skips_what_is_verified_and_refuses_offline_misses() {
        /// A stand-in download: the real one verifies what it wrote, so this serves the
        /// bytes the asked-for digest belongs to and nothing else.
        struct Fake;
        impl Fetch for Fake {
            async fn fetch(&self, _url: &str, sha: &str, dest: &Path, _mode: u32) -> Result<()> {
                let bytes = match sha {
                    SUM_VK => BYTES_VK,
                    SUM_AGENT => BYTES_AGENT,
                    other => bail!("nothing published under {other}"),
                };
                std::fs::write(dest, bytes)?;
                Ok(())
            }
        }
        /// One that must never be called: `--offline` fetches nothing.
        struct Never;
        impl Fetch for Never {
            async fn fetch(&self, _url: &str, _sha: &str, _dest: &Path, _mode: u32) -> Result<()> {
                unreachable!("--offline must not download")
            }
        }

        let dir = tmpdir("install");
        let lock = sample();
        // vk is in the cache with the right contents; vk-agent is not there at all.
        std::fs::write(dir.join("vk"), BYTES_VK).unwrap();
        let plan = plan_install(&lock, &dir, "linux-x86_64", &[]).unwrap();
        assert_eq!(plan[0].step, Step::Cached, "{plan:?}");
        assert!(matches!(plan[1].step, Step::Fetch { .. }), "{plan:?}");

        // Offline names the missing artifact rather than the URL it will not fetch.
        let err = run_install(&plan, &dir, true, &Never)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("vk-agent") && err.contains("--offline"),
            "{err}"
        );

        // A file that no longer matches is fetched again, not trusted for being there.
        std::fs::write(dir.join("vk"), "tampered").unwrap();
        let plan = plan_install(&lock, &dir, "linux-x86_64", &[]).unwrap();
        assert!(matches!(plan[0].step, Step::Fetch { .. }), "{plan:?}");
        run_install(&plan, &dir, false, &Fake).await.unwrap();
        let plan = plan_install(&lock, &dir, "linux-x86_64", &[]).unwrap();
        assert!(plan.iter().all(|p| p.step == Step::Cached), "{plan:?}");

        // A filter narrows the plan, and names an artifact the lock does not carry.
        let one = plan_install(&lock, &dir, "linux-x86_64", &["vk".to_string()]).unwrap();
        assert_eq!(one.len(), 1);
        assert!(plan_install(&lock, &dir, "linux-x86_64", &["nope".to_string()]).is_err());
        // Nothing is locked for this platform: an install that installs nothing has to say
        // so, and name the platforms the lock does cover.
        let err = plan_install(&lock, &dir, "macos-aarch64", &[])
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("nothing for macos-aarch64") && err.contains("linux-x86_64"),
            "{err}"
        );
    }

    // The cache follows the user's environment, with the override first: a project's
    // artifacts are cache data, not something to scatter through $HOME.
    #[test]
    fn cache_root_follows_the_environment() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            cache_root_from(os("/over"), os("/xdg"), os("/home/u")).unwrap(),
            Path::new("/over")
        );
        assert_eq!(
            cache_root_from(None, os("/xdg"), os("/home/u")).unwrap(),
            Path::new("/xdg/virtkit/toolchain")
        );
        assert_eq!(
            cache_root_from(Some(OsString::new()), None, os("/home/u")).unwrap(),
            Path::new("/home/u/.cache/virtkit/toolchain")
        );
        assert!(cache_root_from(None, None, None).is_err());
    }

    // The floor and the pin are different questions: only an older vk is worth a word.
    #[test]
    fn a_vk_is_placed_against_the_lock() {
        assert_eq!(against_lock("0.60.0", "0.60.0"), "the locked release");
        assert_eq!(against_lock("0.61.0", "0.60.0"), "newer than the lock");
        assert_eq!(against_lock("0.59.0", "0.60.0"), "older than the lock");
        assert_eq!(against_lock("0.9.0", "0.10.0"), "older than the lock");
        assert_eq!(
            against_lock("nightly", "0.60.0"),
            "not comparable to the lock"
        );
    }
}
