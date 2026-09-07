//! The VS Code adapter for `vk dev code`: which editor, which server in the guest, and the
//! reconciliation that brings that server to what `[dev.editor.vscode]` describes.
//!
//! Remote-SSH installs its server into the guest home after the connection is up, so the
//! work here cannot be a `create` hook: it is a separate operation, started by `vk dev code`
//! as a detached host process and joined by later attachments. The editor is launched at
//! once — VM readiness never waits for the server, and the server never waits for this.
//!
//! The operation is host-driven and needs nothing in the guest but the server itself. Every
//! guest step is a `vk dev exec` whose exit status is the answer — a probe for the server of
//! exactly the host editor's commit, a probe per extension, an install, a settings merge run
//! by the server's own `node` — so nothing depends on capturing guest output.
//!
//! Its files live under `<state-dir>/editor/`: a `lock` the running operation holds, a log
//! and a completion stamp per `<channel>-<commit>`. The stamp holds a digest of what was
//! applied; a later attachment re-verifies the extensions before trusting it.

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use vk_core::exec::client::Stdin;

use crate::dev::plan::{Plan, VsCodePlan};

/// The editors `vk dev code` looks for, in order, when none is named.
pub const EDITORS: [&str; 5] = ["code", "code-insiders", "codium", "vscodium", "code-oss"];

/// How long the reconciliation waits for Remote-SSH to install the server.
const SERVER_WAIT: Duration = Duration::from_secs(15 * 60);
const SERVER_POLL: Duration = Duration::from_secs(3);

/// A release channel, which fixes where the server keeps itself in the guest home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Insiders,
    Codium,
    Oss,
}

impl Channel {
    /// The channel a binary name stands for. WAB's `vscode` wrapper is the stable build.
    pub fn of(binary_name: &str) -> Channel {
        match binary_name {
            "code-insiders" => Channel::Insiders,
            "codium" | "vscodium" => Channel::Codium,
            "code-oss" => Channel::Oss,
            _ => Channel::Stable,
        }
    }

    /// The server data directory, relative to the guest home.
    pub fn data_dir(self) -> &'static str {
        match self {
            Channel::Stable => ".vscode-server",
            Channel::Insiders => ".vscode-server-insiders",
            Channel::Codium => ".vscodium-server",
            Channel::Oss => ".vscode-server-oss",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Insiders => "insiders",
            Channel::Codium => "codium",
            Channel::Oss => "oss",
        }
    }

    /// The host extension that makes Remote-SSH work for this channel. Finding the editor is
    /// not evidence that it can attach; one of these is.
    fn remote_extensions(self) -> &'static [&'static str] {
        match self {
            Channel::Stable | Channel::Insiders => &["ms-vscode-remote.remote-ssh"],
            Channel::Codium | Channel::Oss => {
                &["jeanp413.open-remote-ssh", "ms-vscode-remote.remote-ssh"]
            }
        }
    }
}

/// A host editor, identified well enough to find its server in the guest.
#[derive(Debug, Clone, PartialEq)]
pub struct Editor {
    pub binary: PathBuf,
    pub channel: Channel,
    pub version: String,
    /// the build commit, which names the server directory
    pub commit: String,
}

/// Resolve the editor: the one named, else the first of [`EDITORS`] on PATH. Its version and
/// commit come from `--version`; its ability to attach from `--list-extensions`.
pub fn select(name: Option<&str>) -> Result<Editor> {
    let binary = match name {
        // A name with a separator in it is the editor itself, not something to look up.
        Some(n) if n.contains('/') => {
            let path = PathBuf::from(n);
            anyhow::ensure!(
                crate::shell::executable(&path),
                "{n} is not an executable file"
            );
            path
        }
        Some(n) => crate::shell::which(n).with_context(|| format!("{n} is not on PATH"))?,
        None => EDITORS
            .iter()
            .find_map(|e| crate::shell::which(e))
            .with_context(|| {
                format!(
                    "no VS Code on PATH (looked for {}) — pass --editor",
                    EDITORS.join(", ")
                )
            })?,
    };
    // Always the resolved binary's own name, never what the caller typed: `--editor
    // /opt/vscode/bin/code-insiders` is the insiders channel, and its server lives under
    // `.vscode-server-insiders`. The detached reconciliation is handed this same path, and
    // has to reach the same conclusion from it.
    let channel = Channel::of(&base_name(&binary));
    let output = std::process::Command::new(&binary)
        .arg("--version")
        .output()
        .with_context(|| format!("running {} --version", binary.display()))?;
    let (version, commit) = parse_version(&String::from_utf8_lossy(&output.stdout))
        .with_context(|| format!("{} --version", binary.display()))?;
    let listed = std::process::Command::new(&binary)
        .arg("--list-extensions")
        .output()
        .with_context(|| format!("running {} --list-extensions", binary.display()))?;
    if !has_remote_extension(&String::from_utf8_lossy(&listed.stdout), channel) {
        bail!(
            "{} ({version}) has no Remote-SSH extension ({}), so it cannot attach to the \
             environment — install one, or name another editor with --editor",
            binary.display(),
            channel.remote_extensions().join(" or ")
        );
    }
    Ok(Editor {
        binary,
        channel,
        version,
        commit,
    })
}

/// `code --version` prints the version, the commit and the arch, one per line.
fn parse_version(text: &str) -> Result<(String, String)> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let version = lines.next().context("printed nothing")?.to_string();
    let commit = lines.next().context("printed no commit")?.to_string();
    if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("expected a commit hash on the second line, got {commit:?}");
    }
    Ok((version, commit))
}

fn has_remote_extension(listed: &str, channel: Channel) -> bool {
    listed.lines().any(|l| {
        let l = l.trim().to_ascii_lowercase();
        channel.remote_extensions().iter().any(|e| l == *e)
    })
}

/// The last component of a path, as a string.
fn base_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The operation's files
// ---------------------------------------------------------------------------

fn editor_dir(plan: &Plan) -> PathBuf {
    plan.state_dir.join("editor")
}

fn lock_path(plan: &Plan) -> PathBuf {
    editor_dir(plan).join("lock")
}

fn slug(editor: &Editor) -> String {
    format!("{}-{}", editor.channel.label(), editor.commit)
}

pub fn log_path(plan: &Plan, editor: &Editor) -> PathBuf {
    editor_dir(plan).join(format!("{}.log", slug(editor)))
}

fn stamp_path(plan: &Plan, editor: &Editor) -> PathBuf {
    editor_dir(plan).join(format!("{}.done", slug(editor)))
}

/// What a reconciliation applies, digested: the extensions, the settings, the project's
/// command, and the server they were applied to. A changed digest is work to redo.
///
/// An encoding failure is an error and not an empty digest: two different plans that both
/// digested nothing would stamp equal, and the second would be skipped as already applied.
pub fn digest(vs: &VsCodePlan, editor: &Editor) -> Result<String> {
    let mut h = Sha256::new();
    h.update(editor.channel.label());
    h.update([0]);
    h.update(&editor.commit);
    for part in [
        serde_json::to_vec(&vs.extensions),
        serde_json::to_vec(&vs.settings),
        serde_json::to_vec(&vs.reconcile),
    ] {
        h.update([0]);
        h.update(part.context("encoding the editor plan")?);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn ensure_dir(plan: &Plan) -> Result<PathBuf> {
    let dir = editor_dir(plan);
    if !dir.is_dir() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    Ok(dir)
}

/// The operation's lock, held for as long as the returned file lives. `None` when another
/// reconciliation holds it.
fn try_lock(plan: &Plan) -> Result<Option<std::fs::File>> {
    use std::os::fd::AsRawFd;
    ensure_dir(plan)?;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path(plan))
        .with_context(|| format!("opening {}", lock_path(plan).display()))?;
    // SAFETY: the fd is owned by `f`; LOCK_NB does not block.
    match unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } {
        0 => Ok(Some(f)),
        _ => Ok(None),
    }
}

/// Who holds the operation's lock, if anyone — read out of `/proc/locks`, never by taking
/// the lock. A probe that takes it holds it for an instant, which is long enough for the
/// reconciliation actually starting beside it to find it busy and join a holder that is
/// only this probe. [`try_lock`] is what claims it; this only ever names a holder.
fn lock_holder(plan: &Plan) -> Option<String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path(plan))
        .ok()?;
    crate::run::flock_holder(&f)
}

// ---------------------------------------------------------------------------
// Starting and joining
// ---------------------------------------------------------------------------

/// What `vk dev code` did about the reconciliation.
#[derive(Debug, PartialEq)]
pub enum Started {
    /// a detached operation, logging to this file
    Spawned { pid: u32, log: PathBuf },
    /// one is already running
    Joined { holder: String },
    /// the config describes no editor state to reconcile
    Nothing,
}

/// Start the reconciliation for `editor` as a detached process, or join the one running.
/// Returns at once; the editor is launched behind it.
pub fn spawn(plan: &Plan, editor: &Editor) -> Result<Started> {
    if plan.vscode.is_none() {
        return Ok(Started::Nothing);
    }
    ensure_dir(plan)?;
    if let Some(holder) = lock_holder(plan) {
        return Ok(Started::Joined { holder });
    }
    let log_path = log_path(plan, editor);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    let mut cmd = std::process::Command::new(crate::spawn::self_exe());
    cmd.args(["dev", "--workspace"])
        .arg(&plan.workspace)
        .args(["--dev-config"])
        .arg(&plan.config)
        .args([
            "--environment",
            &plan.environment,
            "editor-reconcile",
            "--editor",
        ])
        .arg(&editor.binary)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().context("duplicating the editor log")?)
        .stderr(log);
    // SAFETY: `pre_exec` runs after fork; `setsid` is async-signal-safe. It detaches the
    // child from the terminal `vk dev code` is about to hand to the editor.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .context("spawning the editor reconciliation (vk dev editor-reconcile)")?;
    Ok(Started::Spawned {
        pid: child.id(),
        log: log_path,
    })
}

// ---------------------------------------------------------------------------
// The reconciliation
// ---------------------------------------------------------------------------

/// How a reconciliation ended.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// applied, and stamped
    Done,
    /// the stamp matched and every extension is present: nothing to do
    Current,
    /// another one holds the lock
    Joined { holder: String },
    /// the config describes no editor state
    Nothing,
}

/// Bring the guest's server for `editor` to what the config says. Runs in the detached
/// process `vk dev code` spawns, or in the foreground for `vk dev editor retry`; prints its
/// progress, which is the log.
pub async fn reconcile(plan: &Plan, editor: &Editor) -> Result<Outcome> {
    let Some(vs) = &plan.vscode else {
        return Ok(Outcome::Nothing);
    };
    let Some(_lock) = try_lock(plan)? else {
        let holder = lock_holder(plan).unwrap_or_else(|| "unknown pid".into());
        println!("virtkit: editor: a reconciliation is already running ({holder})");
        return Ok(Outcome::Joined { holder });
    };
    let want = digest(vs, editor)?;
    let data = format!("{}/{}", vs.home, editor.channel.data_dir());
    println!(
        "virtkit: editor: {} {} ({}), server data {data}, {} extension(s), {} setting(s){}",
        editor.channel.label(),
        editor.version,
        &editor.commit[..12],
        vs.extensions.len(),
        vs.settings.as_object().map(|o| o.len()).unwrap_or(0),
        if vs.reconcile.is_some() {
            ", a reconcile command"
        } else {
            ""
        }
    );

    // The server of exactly this commit, wherever Remote-SSH puts it.
    let cli = wait_for_server(plan, &data, &editor.commit).await?;
    println!("virtkit: editor: server {cli}");

    // A stamp is a claim; the extensions are the evidence.
    let stamped = std::fs::read_to_string(stamp_path(plan, editor)).is_ok_and(|s| s.trim() == want);
    let missing = missing_extensions(plan, &cli, &vs.extensions).await?;
    if stamped && missing.is_empty() {
        println!("virtkit: editor: already reconciled ({})", &want[..12]);
        return Ok(Outcome::Current);
    }

    let mut failures = Vec::new();
    for ext in &missing {
        println!("virtkit: editor: installing {ext}");
        // Under its own session where `setsid` exists: an attaching window's cleanup has been
        // seen killing the process group of an install in flight.
        let ok = run_in_guest(
            plan,
            "if command -v setsid >/dev/null 2>&1; then exec setsid -w \"$0\" \"$@\"; fi; \
             exec \"$0\" \"$@\"",
            &[cli.as_str(), "--install-extension", ext, "--force"],
            &[],
        )
        .await;
        match ok {
            Ok(()) => {}
            Err(e) => {
                eprintln!("virtkit: editor: {ext}: {e:#}");
                failures.push(ext.clone());
            }
        }
    }
    if vs.settings.as_object().is_some_and(|o| !o.is_empty()) {
        println!("virtkit: editor: applying settings");
        let server = Path::new(&cli)
            .parent()
            .and_then(Path::parent)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let settings_file = format!("{data}/data/Machine/settings.json");
        let json = serde_json::to_string(&vs.settings).context("encoding the settings")?;
        if let Err(e) = run_in_guest(
            plan,
            "exec \"$0/node\" -e \"$1\" \"$2\" \"$3\"",
            &[
                server.as_str(),
                MERGE_SETTINGS_JS,
                settings_file.as_str(),
                json.as_str(),
            ],
            &[],
        )
        .await
        {
            eprintln!("virtkit: editor: settings: {e:#}");
            failures.push("settings".into());
        }
    }
    if let Some(hook) = &vs.reconcile {
        let env = [
            ("VK_VSCODE_CLI".to_string(), cli.clone()),
            ("VK_VSCODE_COMMIT".to_string(), editor.commit.clone()),
            (
                "VK_VSCODE_CHANNEL".to_string(),
                editor.channel.label().to_string(),
            ),
            ("VK_VSCODE_DATA".to_string(), data.clone()),
        ];
        if let Err(e) = crate::dev::run_hook(
            plan,
            "editor.vscode.reconcile",
            hook,
            crate::dev::Where::Guest,
            &env,
        )
        .await
        {
            eprintln!("virtkit: editor: {e:#}");
            failures.push("reconcile".into());
        }
    }
    if !failures.is_empty() {
        bail!(
            "editor reconciliation incomplete ({}); the next `vk dev code` or `vk dev editor \
             retry` tries again",
            failures.join(", ")
        );
    }
    let stamp = stamp_path(plan, editor);
    let tmp = stamp.with_extension("tmp");
    std::fs::write(&tmp, &want).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &stamp).with_context(|| format!("publishing {}", stamp.display()))?;
    println!("virtkit: editor: reconciled ({})", &want[..12]);
    Ok(Outcome::Done)
}

/// Which of `wanted` the server does not have.
///
/// One `--list-extensions` answers for all of them — starting the server CLI once per
/// extension is what this avoids — and only a "no" costs a pass per extension to find out
/// which. `grep -F` matches the id as text: `-qix` alone treats `.` as a basic regex and
/// reads a near-miss id as installed.
async fn missing_extensions(plan: &Plan, cli: &str, wanted: &[String]) -> Result<Vec<String>> {
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    const ALL_PRESENT: &str = "list=$(\"$0\" --list-extensions 2>/dev/null) || exit 1; \
                               shift; for id do \
                               printf '%s\\n' \"$list\" | grep -qixF -- \"$id\" || exit 1; \
                               done";
    let mut argv: Vec<&str> = vec![cli];
    argv.extend(wanted.iter().map(String::as_str));
    if probe(plan, ALL_PRESENT.to_string(), &argv).await? {
        return Ok(Vec::new());
    }
    const ONE: &str = "\"$0\" --list-extensions 2>/dev/null | grep -qixF -- \"$1\"";
    let mut missing = Vec::new();
    for ext in wanted {
        if !probe(plan, ONE.to_string(), &[cli, ext.as_str()]).await? {
            missing.push(ext.clone());
        }
    }
    Ok(missing)
}

/// Wait for the server of `commit` under `data` and return its CLI path. Both layouts
/// Remote-SSH has used are tried, a half-extracted `.staging` tree is not one of them, and
/// the first that answers is the one — for this commit only, never "the first server found".
async fn wait_for_server(plan: &Plan, data: &str, commit: &str) -> Result<String> {
    let candidates = server_candidates(data, commit);
    let deadline = std::time::Instant::now() + SERVER_WAIT;
    let mut announced = false;
    loop {
        for c in &candidates {
            if probe(plan, "test -x \"$0\"".to_string(), &[c.as_str()]).await? {
                return Ok(c.clone());
            }
        }
        if !announced {
            println!(
                "virtkit: editor: waiting for Remote-SSH to install server {} under {data} …",
                &commit[..12]
            );
            announced = true;
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "no server for commit {} appeared under {data} within {}s — is the editor \
                 connected to this environment?",
                &commit[..12],
                SERVER_WAIT.as_secs()
            );
        }
        tokio::time::sleep(SERVER_POLL).await;
    }
}

/// Where a server of `commit` may be: the current per-quality layout, then the legacy one.
fn server_candidates(data: &str, commit: &str) -> Vec<String> {
    let mut out: Vec<String> = ["Stable", "Insiders", "Exploration"]
        .iter()
        .map(|q| format!("{data}/cli/servers/{q}-{commit}/server/bin/code-server"))
        .collect();
    out.push(format!("{data}/bin/{commit}/bin/code-server"));
    out
}

/// Merge the JSON in `argv[3]` into the settings file `argv[2]`, written whole and renamed
/// into place. Run by the server's own `node`, so the guest image needs nothing. A settings
/// file that is not plain JSON (comments) is left alone with an error, rather than rewritten
/// without them.
///
/// The merge is one level deep, deliberately: a key the config names is that key's value,
/// replacing whatever was there. So `editor.vscode.settings` keeps every key it does not
/// name, and replaces whole the ones it does — `{"a": {"b": 1}}` leaves no `a.c` behind. A
/// deep merge would instead make a nested setting impossible to remove from the config, and
/// VS Code's own settings are addressed as whole dotted keys anyway.
///
/// The staging file is created 0600 and unlinked if the rename does not happen, so a failed
/// merge leaves nothing readable beside the settings.
const MERGE_SETTINGS_JS: &str = r#"
const fs = require('fs'), path = require('path');
const [file, json] = process.argv.slice(1);
let cur = {};
try { cur = JSON.parse(fs.readFileSync(file, 'utf8')); }
catch (e) { if (e.code !== 'ENOENT') { console.error(file + ': not plain JSON, not touched: ' + e.message); process.exit(2); } }
Object.assign(cur, JSON.parse(json));
fs.mkdirSync(path.dirname(file), { recursive: true });
const tmp = file + '.vk-tmp';
try {
  fs.writeFileSync(tmp, JSON.stringify(cur, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
} catch (e) {
  try { fs.unlinkSync(tmp); } catch (_) {}
  throw e;
}
"#;

/// Run `script` through the guest's `sh -c`, with `args` as `$0 $1 …`, as the configured
/// user with `exec-env`. Exit status zero is success.
async fn run_in_guest(
    plan: &Plan,
    script: &str,
    args: &[&str],
    env: &[(String, String)],
) -> Result<()> {
    let mut argv = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let result =
        crate::dev::exec_in_guest_with(plan, &argv, None, false, Stdin::Closed, env).await?;
    match result.code {
        Some(0) => Ok(()),
        Some(code) => bail!("exited {code}"),
        None => bail!("killed by signal {}", result.signal.unwrap_or_default()),
    }
}

/// A yes/no question to the guest: the script's exit status. Only a failure to *ask* is an
/// error.
async fn probe(plan: &Plan, script: String, args: &[&str]) -> Result<bool> {
    let mut argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
    argv.extend(args.iter().map(|a| a.to_string()));
    let result =
        crate::dev::exec_in_guest_with(plan, &argv, None, false, Stdin::Closed, &[]).await?;
    Ok(result.code == Some(0))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// `vk dev editor status` as data: what the config describes, whether an operation holds the
/// lock, and what has been reconciled. The text rendering and `--json` are the same view.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct StatusView {
    /// absent when the config has no `[dev.editor.vscode]`, which is the whole answer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) configured: Option<Configured>,
    /// who holds the operation's lock, when anyone does
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) running: Option<String>,
    /// one per completed reconciliation still stamped under the state directory
    pub(crate) reconciled: Vec<Reconciled>,
    pub(crate) logs: Vec<Log>,
}

/// What `[dev.editor.vscode]` asks for.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Configured {
    pub(crate) extensions: usize,
    pub(crate) settings: usize,
    pub(crate) reconcile_command: bool,
    /// whether the server's storage outlives the environment's image generation
    pub(crate) persistent: bool,
}

/// One completed reconciliation, named by the server it was applied to.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Reconciled {
    /// `<channel>-<commit>`, the server this concerns
    pub(crate) server: String,
    /// how long ago it was stamped, when the stamp's time can be read
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) age_secs: Option<u64>,
}

/// One reconciliation log kept under the state directory.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Log {
    pub(crate) server: String,
    pub(crate) path: PathBuf,
}

/// `vk dev editor status`, read from the config and the operation's own files.
pub(crate) fn status_view(plan: &Plan) -> StatusView {
    let configured = plan.vscode.as_ref().map(|vs| Configured {
        extensions: vs.extensions.len(),
        settings: vs.settings.as_object().map(|o| o.len()).unwrap_or(0),
        reconcile_command: vs.reconcile.is_some(),
        persistent: vs.persistent,
    });
    let mut view = StatusView {
        configured,
        running: lock_holder(plan),
        reconciled: Vec::new(),
        logs: Vec::new(),
    };
    if view.configured.is_none() {
        return view;
    }
    let mut entries: Vec<_> = std::fs::read_dir(editor_dir(plan))
        .map(|rd| rd.flatten().collect())
        .unwrap_or_default();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(slug) = name.strip_suffix(".done") {
            let age_secs = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| crate::vms::unix_now().saturating_sub(d.as_secs()));
            view.reconciled.push(Reconciled {
                server: short_slug(slug),
                age_secs,
            });
        } else if let Some(slug) = name.strip_suffix(".log") {
            view.logs.push(Log {
                server: short_slug(slug),
                path: e.path(),
            });
        }
    }
    view
}

/// A `<channel>-<commit>` slug with the commit cut to the twelve characters everything else
/// prints — the whole hash doubles the width and tells the reader nothing more.
fn short_slug(slug: &str) -> String {
    match slug.split_once('-') {
        Some((channel, commit)) => {
            let short: String = commit.chars().take(12).collect();
            format!("{channel}-{short}")
        }
        None => slug.to_string(),
    }
}

/// `vk dev editor status`: the operation's own state, apart from the VM's.
pub fn status(plan: &Plan) -> String {
    let view = status_view(plan);
    let Some(c) = &view.configured else {
        return "editor      no [dev.editor.vscode] in the config\n".into();
    };
    let mut out = format!(
        "editor      {} extension(s), {} setting(s){}, state {}\n",
        c.extensions,
        c.settings,
        match c.reconcile_command {
            true => ", a reconcile command",
            false => "",
        },
        match c.persistent {
            true => "persistent",
            false => "ephemeral",
        }
    );
    match &view.running {
        Some(holder) => out.push_str(&format!("operation   running ({holder})\n")),
        None => out.push_str("operation   idle\n"),
    }
    for r in &view.reconciled {
        let when = r.age_secs.map(|s| format!("{s}s ago")).unwrap_or_default();
        out.push_str(&format!("reconciled  {} {when}\n", r.server));
    }
    for l in &view.logs {
        out.push_str(&format!("log         {}: {}\n", l.server, l.path.display()));
    }
    if view.reconciled.is_empty() {
        out.push_str("reconciled  never — `vk dev code` starts it\n");
    }
    out
}

/// How much of a log `vk dev editor log` prints: a reconciliation that retried for the
/// quarter of an hour it waits for the server writes more than anyone reads, and it is the
/// end that says how it went.
const LOG_TAIL_BYTES: usize = 64 * 1024;

/// `vk dev editor log`: the newest log, its last [`LOG_TAIL_BYTES`] where it is longer.
pub fn latest_log(plan: &Plan) -> Result<String> {
    let dir = editor_dir(plan);
    let newest = std::fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".log"))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    let Some(entry) = newest else {
        bail!("no editor log under {} yet", dir.display());
    };
    let path = entry.path();
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = format!("== {}\n", path.display());
    match text.len() > LOG_TAIL_BYTES {
        // On a character boundary, so a multi-byte line at the cut does not become garbage.
        true => {
            let cut = text.len() - LOG_TAIL_BYTES;
            let from = (cut..text.len())
                .find(|i| text.is_char_boundary(*i))
                .unwrap_or(text.len());
            out.push_str(&format!("… {cut} earlier byte(s) not shown\n"));
            out.push_str(&text[from..]);
        }
        false => out.push_str(&text),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_follow_the_binary_name_and_name_their_server_directory() {
        assert_eq!(Channel::of("code"), Channel::Stable);
        assert_eq!(Channel::of("vscode"), Channel::Stable, "WAB's wrapper");
        assert_eq!(Channel::of("code-insiders"), Channel::Insiders);
        assert_eq!(Channel::of("codium"), Channel::Codium);
        assert_eq!(Channel::of("vscodium"), Channel::Codium);
        assert_eq!(Channel::of("code-oss"), Channel::Oss);
        assert_eq!(Channel::Stable.data_dir(), ".vscode-server");
        assert_eq!(Channel::Insiders.data_dir(), ".vscode-server-insiders");
        assert_eq!(Channel::Codium.data_dir(), ".vscodium-server");
    }

    #[test]
    fn the_version_output_yields_the_commit_and_nothing_less_will_do() {
        let (v, c) =
            parse_version("1.93.1\n38c31bc77e0dd6ae88a4e9cc93428cc27a56ba40\nx64\n").unwrap();
        assert_eq!(v, "1.93.1");
        assert_eq!(c, "38c31bc77e0dd6ae88a4e9cc93428cc27a56ba40");
        assert!(parse_version("1.93.1\nnot-a-commit\nx64\n").is_err());
        assert!(parse_version("1.93.1\n").is_err());
        assert!(parse_version("").is_err());
    }

    #[test]
    fn attaching_needs_the_remote_extension_not_only_the_binary() {
        assert!(has_remote_extension(
            "ms-python.python\nMS-vscode-remote.remote-ssh\n",
            Channel::Stable
        ));
        assert!(!has_remote_extension("ms-python.python\n", Channel::Stable));
        assert!(has_remote_extension(
            "jeanp413.open-remote-ssh\n",
            Channel::Codium
        ));
        assert!(!has_remote_extension(
            "jeanp413.open-remote-ssh\n",
            Channel::Stable,
        ));
    }

    #[test]
    fn the_server_is_looked_for_by_commit_in_both_layouts() {
        let c = server_candidates("/home/dev/.vscode-server", "abc");
        assert_eq!(
            c[0],
            "/home/dev/.vscode-server/cli/servers/Stable-abc/server/bin/code-server"
        );
        assert!(
            c.iter()
                .any(|p| p == "/home/dev/.vscode-server/bin/abc/bin/code-server")
        );
        assert!(
            c.iter().all(|p| p.contains("abc")),
            "never another commit's server"
        );
    }

    fn editor(commit: &str) -> Editor {
        Editor {
            binary: PathBuf::from("/usr/bin/code"),
            channel: Channel::Stable,
            version: "1.93.1".into(),
            commit: commit.into(),
        }
    }

    fn vs(extensions: &[&str]) -> VsCodePlan {
        VsCodePlan {
            persistent: true,
            home: "/home/dev".into(),
            reconcile: None,
            extensions: extensions.iter().map(|s| s.to_string()).collect(),
            settings: serde_json::json!({"a": 1}),
        }
    }

    #[test]
    fn the_digest_changes_with_what_is_applied_and_with_the_server() {
        let d = |plan: &VsCodePlan, ed: &Editor| digest(plan, ed).unwrap();
        let a = d(&vs(&["x"]), &editor("1111"));
        assert_eq!(a, d(&vs(&["x"]), &editor("1111")), "stable");
        assert_ne!(a, d(&vs(&["x", "y"]), &editor("1111")));
        assert_ne!(
            a,
            d(&vs(&["x"]), &editor("2222")),
            "another server, another job"
        );
        let mut with_hook = vs(&["x"]);
        with_hook.reconcile = Some(crate::dev::plan::HookPlan::Command(
            crate::dev::plan::HookCommand {
                run: crate::dev::config::Command::Shell("true".into()),
                cwd: None,
                timeout_secs: None,
                required: true,
            },
        ));
        assert_ne!(a, d(&with_hook, &editor("1111")));
    }

    fn plan_in(dir: &Path) -> Plan {
        Plan {
            workspace: dir.join("repo"),
            config: dir.join("repo/.virtkit/config.toml"),
            environment: "dev".into(),
            state_dir: dir.join("state"),
            source: crate::dev::plan::Source::Image {
                reference: "x".into(),
            },
            workspace_folder: Some("/w".into()),
            user: Some("dev".into()),
            freshness: crate::dev::config::Freshness::Ask,
            cpus: None,
            mem: None,
            mounts: vec![],
            container_env: vec![],
            exec_env: vec![],
            endpoints: vec![],
            host_exec: None,
            ssh_agent: false,
            cache: Default::default(),
            requires: Default::default(),
            cached_only: false,
            fallback_target: None,
            tasks: Vec::new(),
            hooks: Default::default(),
            vscode: Some(vs(&["x"])),
            managed_dirs: vec![],
            unresolved: vec![],
            secrets: Default::default(),
        }
    }

    #[test]
    fn the_operation_has_a_lock_a_log_and_a_stamp_under_the_state_dir() {
        let dir = std::env::temp_dir().join(format!("vk-deveditor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let plan = plan_in(&dir);
        let ed = editor("abcdef0123456789abcdef0123456789abcdef01");
        assert!(status(&plan).contains("never"), "{}", status(&plan));
        assert!(latest_log(&plan).is_err());

        // One holder at a time; a probe sees who.
        let held = try_lock(&plan).unwrap().expect("free");
        assert!(try_lock(&plan).unwrap().is_none(), "held");
        assert!(lock_holder(&plan).is_some());
        assert!(status(&plan).contains("running"), "{}", status(&plan));
        drop(held);
        assert!(lock_holder(&plan).is_none());

        // The files are named for the server they concern, beside the lock, all private.
        assert_eq!(
            log_path(&plan, &ed),
            dir.join("state/editor/stable-abcdef0123456789abcdef0123456789abcdef01.log")
        );
        std::fs::write(stamp_path(&plan, &ed), digest(&vs(&["x"]), &ed).unwrap()).unwrap();
        std::fs::write(log_path(&plan, &ed), "virtkit: editor: reconciled\n").unwrap();
        let s = status(&plan);
        assert!(s.contains("reconciled  stable-abcdef012345"), "{s}");
        assert!(latest_log(&plan).unwrap().contains("reconciled"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.join("state/editor"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        // Nothing here is reachable through a config mount: the state dir's `editor` entry
        // is reserved by the plan.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in `code` binary: `--version` prints a version, a commit and an arch, and
    /// `--list-extensions` names the Remote-SSH extension [`select`] insists on.
    fn fake_editor(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o755)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(
            &mut f,
            b"#!/bin/sh\n\
              case \"$1\" in\n\
              --version) printf '1.93.1\\nabcdef0123456789abcdef0123456789abcdef01\\nx64\\n' ;;\n\
              --list-extensions) printf 'ms-vscode-remote.remote-ssh\\n' ;;\n\
              esac\n",
        )
        .unwrap();
        path
    }

    #[test]
    fn the_channel_follows_the_resolved_binary_even_when_it_is_a_path() {
        let dir = std::env::temp_dir().join(format!("vk-deveditor-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = fake_editor(&dir, "code-insiders");

        // The channel comes from the binary that was resolved, not from what was typed —
        // an absolute path to an insiders build is the insiders channel, and its server
        // lives under the insiders data directory.
        let ed = select(Some(&path.to_string_lossy())).unwrap();
        assert_eq!(ed.channel, Channel::Insiders);
        assert_eq!(ed.channel.data_dir(), ".vscode-server-insiders");
        assert_eq!(ed.binary, path);
        assert_eq!(ed.version, "1.93.1");
        // Which is what the detached reconciliation is handed, and has to agree on.
        assert_eq!(Channel::of(&base_name(&ed.binary)), Channel::Insiders);

        // A path that is not an executable file is refused before anything is run.
        let e = select(Some(&dir.join("nope").to_string_lossy())).unwrap_err();
        assert!(format!("{e:#}").contains("not an executable file"), "{e:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stamp_is_only_believed_for_the_plan_and_server_it_names() {
        let dir = std::env::temp_dir().join(format!("vk-deveditor-stamp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut plan = plan_in(&dir);
        let ed = editor("abcdef0123456789abcdef0123456789abcdef01");
        ensure_dir(&plan).unwrap();

        // What `reconcile` writes, and what it reads back to decide there is nothing to do.
        let want = digest(plan.vscode.as_ref().unwrap(), &ed).unwrap();
        std::fs::write(stamp_path(&plan, &ed), format!("{want}\n")).unwrap();
        let stamped = |plan: &Plan, ed: &Editor, want: &str| {
            std::fs::read_to_string(stamp_path(plan, ed)).is_ok_and(|s| s.trim() == want)
        };
        assert!(
            stamped(&plan, &ed, &want),
            "the trailing newline is trimmed"
        );

        // Another server is another job, stamped under a name of its own.
        let other = editor("1111111111111111111111111111111111111111");
        assert_ne!(stamp_path(&plan, &other), stamp_path(&plan, &ed));
        assert!(!stamped(&plan, &other, &want));

        // And a changed plan no longer matches the stamp that is there.
        plan.vscode = Some(vs(&["x", "y"]));
        let now = digest(plan.vscode.as_ref().unwrap(), &ed).unwrap();
        assert_ne!(now, want);
        assert!(!stamped(&plan, &ed, &now));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_status_view_is_what_the_text_renders() {
        let dir = std::env::temp_dir().join(format!("vk-deveditor-view-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let plan = plan_in(&dir);
        let ed = editor("abcdef0123456789abcdef0123456789abcdef01");
        ensure_dir(&plan).unwrap();
        std::fs::write(stamp_path(&plan, &ed), digest(&vs(&["x"]), &ed).unwrap()).unwrap();
        std::fs::write(log_path(&plan, &ed), "virtkit: editor: reconciled\n").unwrap();

        let view = status_view(&plan);
        let c = view.configured.as_ref().unwrap();
        assert_eq!((c.extensions, c.settings, c.persistent), (1, 1, true));
        assert!(!c.reconcile_command);
        assert_eq!(view.running, None);
        // The commit is cut to twelve characters, the same in the view and the text.
        assert_eq!(view.reconciled.len(), 1);
        assert_eq!(view.reconciled[0].server, "stable-abcdef012345");
        assert_eq!(view.logs.len(), 1);
        assert_eq!(view.logs[0].path, log_path(&plan, &ed));
        assert!(status(&plan).contains("reconciled  stable-abcdef012345"));

        // With no `[dev.editor.vscode]` the view says only that, and reads no files.
        let mut none = plan.clone();
        none.vscode = None;
        let view = status_view(&none);
        assert_eq!(view.configured, None);
        assert!(view.reconciled.is_empty() && view.logs.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_to_reconcile_without_an_editor_section() {
        let dir = std::env::temp_dir().join(format!("vk-deveditor-none-{}", std::process::id()));
        let mut plan = plan_in(&dir);
        plan.vscode = None;
        let ed = editor("abcdef0123456789abcdef0123456789abcdef01");
        assert_eq!(spawn(&plan, &ed).unwrap(), Started::Nothing);
        assert!(!dir.exists(), "no state created for nothing");
        assert!(status(&plan).contains("no [dev.editor.vscode]"));
    }
}
