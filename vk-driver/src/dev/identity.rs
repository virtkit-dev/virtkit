//! What the environment was booted from, and how a later plan differs from it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::dev::plan::{HookPlan, Plan, Source};

use super::hooks::stamped;
use super::session::running_vm;
use super::{GENERATION_MARKER, Identity};

/// What this `vk` records as an environment's creator: what `vk --version` prints.
pub(super) fn own_version() -> String {
    format!("vk {} ({})", env!("CARGO_PKG_VERSION"), env!("VK_GIT_HASH"))
}

/// The release that created a running environment, when it is older than this vk: the
/// injected agent and guest vk are that release's, so a newer host vk may not open what
/// they produce (image formats, protocols) until the environment is restarted. Unparsable
/// or absent records — from a vk that did not write one — say nothing.
fn older_creator(created_by: &str) -> Option<String> {
    let recorded: crate::check::Version = created_by.split_whitespace().nth(1)?.parse().ok()?;
    let own = crate::check::Version::own().ok()?;
    (recorded < own).then(|| recorded.to_string())
}

/// The note `up` prints when it reuses an environment an older vk created.
pub(super) fn note_older_creator(identity: &Identity) {
    if let Some(older) = older_creator(&identity.created_by) {
        eprintln!(
            "virtkit: it was created by vk {older}; this is {} — `vk dev refresh` restarts it \
             with this one (needed when the two disagree on image or protocol formats)",
            env!("CARGO_PKG_VERSION")
        );
    }
}

/// The token a managed directory carries, empty for one that has none — a directory an
/// older `vk` created, or one this host could not write.
pub(super) fn marker_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join(GENERATION_MARKER))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// `<state-dir>/dev.json`: what the environment was booted from, written by the parent of
/// the boot that produced it — last of all, once the endpoints are published and the start
/// hooks have run, so its presence is what says the environment is ready.
pub(super) fn identity_path(plan: &Plan) -> PathBuf {
    plan.state_dir.join("dev.json")
}

/// `<state-dir>/not-ready`: the VM is up with no identity. The parent readying it writes one
/// naming itself as it starts, and removes it once the identity is written; a failure
/// rewrites it naming nobody. A joiner waits while the readier it names is alive, and takes
/// the environment over once it names nobody or a process that is gone — killed mid-readying,
/// say.
///
/// Where there is no marker at all, a joiner waits out `READY_WAIT` and fails, as it did
/// before this existed: a parent killed between the VM coming up and its writing one, or one
/// that cannot name itself (no start time to read from procfs).
fn not_ready_path(plan: &Plan) -> PathBuf {
    plan.state_dir.join("not-ready")
}

/// `<state-dir>/not-ready.lock`, held across every read-modify-write of the marker, so a
/// claim, a readier's update and a readier dropping it never interleave.
fn lock_not_ready(plan: &Plan) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = plan.state_dir.join("not-ready.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.lock()
        .with_context(|| format!("locking {}", path.display()))?;
    Ok(f)
}

/// A VM's managing `vk run` and registration time. These tie a marker to its VM so a
/// replaced VM's parent cannot leave a marker that a joiner mistakes for the current VM's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct VmTie {
    pub pid: u32,
    pub created_secs: u64,
}

impl VmTie {
    pub(super) fn of(vm: &crate::vms::VmEntry) -> Self {
        Self {
            pid: vm.pid,
            created_secs: vm.created_secs,
        }
    }
}

/// A process by pid and start time, so a pid handed out again is not taken for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Readier {
    pub pid: u32,
    /// `starttime` from `/proc/<pid>/stat`
    pub started: u64,
}

impl Readier {
    /// `pid` as it is now; `None` once it is gone or has exited, or where procfs does not say.
    pub(super) fn of(pid: u32) -> Option<Self> {
        Some(Self {
            pid,
            started: crate::usage::proc_starttime(i32::try_from(pid).ok()?)?,
        })
    }

    /// Whether this process is still the one running under its pid.
    fn alive(&self) -> bool {
        Self::of(self.pid) == Some(*self)
    }
}

/// What the marker records: the VM, the identity its readying would write, who is readying
/// it, and how the readying stands.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct NotReady {
    pub vm: VmTie,
    pub digest: String,
    pub manifest: serde_json::Value,
    /// what that identity would have recorded as [`Identity::booted_secs`], carried over by
    /// a claim so the environment's age stays that of its boot
    pub booted_secs: u64,
    /// the parent readying the VM; `None` once its readying failed
    pub readier: Option<Readier>,
    /// why the readying failed; empty while it is under way
    pub why: String,
}

impl NotReady {
    /// What became of the readying, for a message: why it failed, or that its parent went
    /// before finishing.
    pub(super) fn reason(&self) -> &str {
        if self.why.is_empty() {
            "the process readying it is gone"
        } else {
            &self.why
        }
    }

    /// Nobody is readying the VM any more: the readying failed, or the parent it names is
    /// gone. A marker that says neither — naming nobody with no failure — is never taken.
    pub(super) fn abandoned(&self) -> bool {
        (!self.why.is_empty() || self.readier.is_some()) && !self.readier.is_some_and(|r| r.alive())
    }
}

/// Write the marker; the caller holds [`lock_not_ready`].
fn write_not_ready(plan: &Plan, left: &NotReady) -> Result<()> {
    let json = serde_json::to_vec(left).context("serializing it")?;
    vk_fs::write_atomic(&not_ready_path(plan), &json, 0o600)
}

/// Record how this process's readying of the VM stands, for joiners and [`claim_not_ready`].
/// Under [`lock_not_ready`], `update` gets the marker if it names this process — a claim
/// left it, or this readying wrote it — and returns the one to write, or `None` for none. A
/// marker another readying holds for the same VM is left alone. Whether one was written.
pub(super) fn mark_own_not_ready(
    plan: &Plan,
    update: impl FnOnce(Option<&NotReady>) -> Option<NotReady>,
) -> bool {
    let written = lock_not_ready(plan).and_then(|_lock| {
        let current = read_not_ready(plan);
        let me = Readier::of(std::process::id());
        let own = current.as_ref().filter(|l| me.is_some() && l.readier == me);
        let Some(left) = update(own) else {
            return Ok(false);
        };
        if own.is_none() && current.as_ref().is_some_and(|c| c.vm == left.vm) {
            return Ok(false);
        }
        write_not_ready(plan, &left).map(|()| true)
    });
    written.unwrap_or_else(|e| {
        eprintln!(
            "virtkit: warning: could not record how readying the environment stands ({e:#}); \
             a `vk dev` joining it waits for this boot to time out instead of taking it over"
        );
        false
    })
}

/// Write `left` whatever the marker holds, as a readying elsewhere would.
#[cfg(test)]
pub(super) fn mark_not_ready(plan: &Plan, left: &NotReady) {
    lock_not_ready(plan)
        .and_then(|_lock| write_not_ready(plan, left))
        .unwrap();
}

/// The marker as it stands, if it is there and readable.
pub(super) fn read_not_ready(plan: &Plan) -> Option<NotReady> {
    serde_json::from_slice(&std::fs::read(not_ready_path(plan)).ok()?).ok()
}

/// What a joiner may do with an environment a failed readying left behind.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LeftBehind {
    /// take it over: it was booted from this config, or from one that differs only in what
    /// readying it applies
    Claim,
    /// booted from a different configuration — what the drift policy decides about
    Drifted,
}

/// What `left` is to a joiner whose config resolves to `digest`/`manifest`, with `running`
/// the VM now up. `None` when the marker describes another VM, or none is up: nothing to
/// take over.
pub(super) fn left_behind(
    left: &NotReady,
    running: Option<VmTie>,
    digest: &str,
    manifest: &serde_json::Value,
) -> Option<LeftBehind> {
    if running != Some(left.vm) {
        return None;
    }
    if left.digest == digest || applied_on_attach(&drift(&left.manifest, manifest)) {
        Some(LeftBehind::Claim)
    } else {
        Some(LeftBehind::Drifted)
    }
}

/// Claim an abandoned marker for `parent_pid`, the next readier. Under [`lock_not_ready`],
/// `still` rechecks the current marker, which may differ from what the caller inspected.
/// Naming the parent makes other joiners wait, so only one retries setup. Returns `None`
/// if the marker can no longer be claimed or the parent cannot be named.
///
/// Clear the recorded failure so a later parent death is reported instead of the old error.
/// Keep the old error in the returned marker.
pub(super) fn claim_not_ready(
    plan: &Plan,
    parent_pid: u32,
    still: impl FnOnce(&NotReady) -> bool,
) -> Option<NotReady> {
    let _lock = lock_not_ready(plan).ok()?;
    let mut left = read_not_ready(plan).filter(|left| left.abandoned() && still(left))?;
    left.readier = Some(Readier::of(parent_pid)?);
    let why = std::mem::take(&mut left.why);
    write_not_ready(plan, &left).ok()?;
    left.why = why;
    Some(left)
}

/// The marker a claim left for this parent to ready `vm` from: `Some` only when it names this
/// process, as it runs now, and that VM. A fresh boot has none.
pub(super) fn claimed_for_me(plan: &Plan, vm: Option<VmTie>) -> Option<NotReady> {
    let _lock = lock_not_ready(plan).ok()?;
    read_not_ready(plan)
        .filter(|l| l.readier.is_some() && l.readier == Readier::of(std::process::id()))
        .filter(|l| Some(l.vm) == vm)
}

/// Remove the marker once this parent is done readying the VM, unless it no longer names
/// this parent: then it is another readying's.
pub(super) fn drop_own_not_ready(plan: &Plan) {
    let Some(me) = Readier::of(std::process::id()) else {
        return;
    };
    let Ok(_lock) = lock_not_ready(plan) else {
        return;
    };
    if read_not_ready(plan).is_some_and(|l| l.readier == Some(me)) {
        let _ = std::fs::remove_file(not_ready_path(plan));
    }
}

/// Clear the marker before a new boot: it describes the VM that boot replaces. Best effort,
/// as for the identity removed beside it; a marker left names that VM, which no joiner takes
/// for the new one.
pub(super) fn clear_not_ready(plan: &Plan) {
    let _lock = lock_not_ready(plan);
    let _ = std::fs::remove_file(not_ready_path(plan));
}

/// What the last boot recorded for this environment. A file that is absent or unreadable —
/// a state dir never booted, or one an older `vk` wrote in another shape — means nothing to
/// compare against, which callers report as unknown rather than mistake for a match.
pub fn read_identity(plan: &Plan) -> Option<Identity> {
    let bytes = std::fs::read(identity_path(plan)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The identity a plan resolves to: a stable digest, and the manifest it digests. Values
/// that came from the host environment are reduced to a fingerprint — they still take part
/// in drift detection, but a token never reaches a file.
///
/// Two passes, because a host-fed value reaches more places than the two environment
/// scopes: the scopes are fingerprinted whole by what [`crate::dev::plan::Vars`] marked, and
/// then every secret occurrence anywhere else in the manifest — a build argument, a task's
/// environment, a mount source, embedded in a larger string or not — is fingerprinted in
/// place, so it takes part in drift detection but never reaches a file.
pub fn identity_of(plan: &Plan, wrapper: Option<&str>) -> Result<(String, serde_json::Value)> {
    let mut manifest = serde_json::to_value(plan).context("serializing the plan")?;
    for scope in ["container_env", "exec_env"] {
        let Some(list) = manifest.get_mut(scope).and_then(|v| v.as_array_mut()) else {
            continue;
        };
        for (entry, source) in list.iter_mut().zip(match scope {
            "container_env" => &plan.container_env,
            _ => &plan.exec_env,
        }) {
            if source.sensitive
                && let Some(obj) = entry.as_object_mut()
            {
                obj.insert("value".into(), fingerprint(&source.value));
            }
        }
    }
    fingerprint_secrets(&mut manifest, &plan.secrets);
    // The host-command allowlist is policy the guest runs against, so a changed one is a
    // changed environment even though nothing in the config moved.
    if let Some(digest) = wrapper {
        manifest["host_exec_wrapper_digest"] = serde_json::Value::String(digest.to_string());
    }
    // Canonical only because `serde_json` writes object keys in insertion order and every
    // map in the plan is a `BTreeMap`: no crate in the graph enables
    // `serde_json/preserve_order`, which would reorder them under feature unification and
    // change every digest at once.
    let canonical = serde_json::to_vec(&manifest).context("serializing the manifest")?;
    Ok((sha256_hex(&canonical), manifest))
}

/// The environment as *materialized*, rather than as configured: the root image it booted,
/// the token each managed directory carries, and the commands `hooks.create` runs.
///
/// Those three are exactly what a creation hook initializes, so its stamp is keyed on this
/// and not on the config digest — a refresh that rebuilt the image, a `storage reset` that
/// recreated a directory, or an edited hook runs it again, while a changed but unrelated
/// config key does not.
pub(super) fn generation_of(plan: &Plan, root: &str) -> String {
    let mut create = std::collections::BTreeMap::new();
    if let Some(hook) = &plan.hooks.create {
        hook_argv(hook, "create", &mut create);
    }
    let storage: Vec<(String, String)> = plan
        .managed_dirs
        .iter()
        .map(|d| (d.display().to_string(), marker_of(d)))
        .collect();
    sha256_hex(
        serde_json::json!({ "root": root, "storage": storage, "create": create }).to_string(),
    )
}

/// What identifies the root image a VM booted.
pub(super) fn root_identity(plan: &Plan, vm: &crate::vms::VmEntry) -> String {
    match (&vm.stale_recipe, &plan.source) {
        // A built image stamps its build key into its ext4 UUID (see `vms::freshness`), so
        // the UUID is the identity of everything that build produced.
        (Some(r), _) => crate::ext4::fs_uuid(&r.root_ext4).map_or_else(
            || format!("root:{}", r.root_ext4.display()),
            |uuid| format!("ext4:{uuid}"),
        ),
        // An image boot records no recipe, and the registry entry keeps nothing else that
        // identifies what was pulled — so the reference stands in, and a tag re-pulled to
        // different content is not seen as a new generation.
        (None, Source::Image { reference }) => format!("image:{reference}"),
        (None, _) => format!("label:{}", vm.label),
    }
}

/// The commands a hook runs, keyed by their place in it: what the generation takes from
/// `hooks.create`, so editing what it runs runs it again while changing its timeout or
/// whether it is required does not.
fn hook_argv(hook: &HookPlan, at: &str, out: &mut std::collections::BTreeMap<String, Vec<String>>) {
    match hook {
        HookPlan::Command(cmd) => {
            out.insert(at.to_string(), cmd.argv());
        }
        HookPlan::Group(group) => {
            for (name, member) in group {
                hook_argv(member, &format!("{at}.{name}"), out);
            }
        }
    }
}

/// The digest the identity carries for the host-command allowlist, over the wrapper as the
/// config names it *now*: the project's own file, which is what an edit changes, rather than
/// the snapshot the last boot left in the state dir — reading the source is what makes an
/// edited `host.wrapper` drift the moment it is edited, and not one boot later. A built-in
/// policy has no source to edit: `host_exec.wrapper` is then the generated file in the state
/// dir, whose text names this vk and this workspace, so either of those moving is the drift.
///
/// `None` when the config asks for no host exec, and best effort otherwise: a wrapper that
/// cannot be read leaves the digest out of the manifest, which reads as a difference rather
/// than as a match.
pub(super) fn wrapper_digest(plan: &Plan) -> Option<String> {
    let host_exec = plan.host_exec.as_ref()?;
    std::fs::read(&host_exec.wrapper).ok().map(sha256_hex)
}

/// The digest of the wrapper the *running* environment was given: the snapshot `boot`
/// published in the state dir, which is the copy the host actually executes. What
/// `after_boot` records, so an edit made while the guest was coming up reads as drift rather
/// than being recorded as if it had booted.
///
/// Best effort: a snapshot that cannot be read leaves the wrapper out of the manifest, which
/// reads as a difference rather than as a match.
pub(super) fn booted_wrapper_digest(plan: &Plan) -> Option<String> {
    plan.host_exec.as_ref()?;
    let body = std::fs::read(plan.state_dir.join("host-exec-wrapper")).ok()?;
    Some(sha256_hex(body))
}

/// What stands in for a value this host supplied: a digest, so the value still takes part
/// in drift detection without ever being written down. [`FINGERPRINT`] is how a reader —
/// and [`drift`] — recognizes one.
fn fingerprint(value: &str) -> serde_json::Value {
    serde_json::Value::String(fingerprint_hex(value))
}

/// A value's fingerprint as a bare string, for replacing it inside a larger one.
fn fingerprint_hex(value: &str) -> String {
    format!("{FINGERPRINT}{}", sha256_hex(value))
}

/// The prefix every fingerprint carries.
const FINGERPRINT: &str = "sha256:";

/// Replace every secret occurrence in `manifest` with a fingerprint of it. Containment, not
/// equality: a `${localEnv:…}` can be embedded in a URL, a path or a build argument, and the
/// secret must not survive there either. Longest first, so a secret that contains another is
/// replaced whole.
fn fingerprint_secrets(
    manifest: &mut serde_json::Value,
    secrets: &std::collections::BTreeSet<String>,
) {
    let mut ordered: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    ordered.sort_by_key(|s| std::cmp::Reverse(s.len()));
    scrub_value(manifest, &ordered);
}

/// Fingerprint every `secrets` occurrence in every string reachable from `value`.
fn scrub_value(value: &mut serde_json::Value, secrets: &[&str]) {
    match value {
        serde_json::Value::String(s) => {
            for secret in secrets {
                if s.contains(secret) {
                    *s = s.replace(secret, &fingerprint_hex(secret));
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(|i| scrub_value(i, secrets)),
        serde_json::Value::Object(map) => map.values_mut().for_each(|v| scrub_value(v, secrets)),
        _ => {}
    }
}

pub(super) fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The identity of the environment that is running for this plan's state dir, if one is.
pub(super) fn live_identity(plan: &Plan) -> Option<Identity> {
    running_vm(plan)?;
    read_identity(plan)
}

/// Publish the identity whole: its presence is what says the environment is ready, so a
/// joiner must never find a half-written one.
pub(super) fn write_identity(plan: &Plan, identity: &Identity) -> Result<()> {
    let json = serde_json::to_vec_pretty(identity).context("serializing the identity")?;
    vk_fs::write_atomic(&identity_path(plan), &json, 0o600)
}

/// `vk dev plan --diff`: what applying the current plan to the running environment would
/// change, and what each change takes — a new session, a host-side step, a restart, or a
/// rebuilt image — so a reader knows whether `vk dev refresh` is worth the interruption.
/// `None` when nothing is running to compare against.
pub fn plan_diff(plan: &Plan) -> Result<Option<String>> {
    let Some(vm) = running_vm(plan) else {
        return Ok(None);
    };
    let recorded = read_identity(plan)
        .context("the running environment recorded no identity to compare against")?;
    let wrapper = wrapper_digest(plan);
    let (digest, current) = identity_of(plan, wrapper.as_deref())?;

    let groups = drift(&recorded.manifest, &current);
    let stale = crate::vms::freshness_all(&vm) == crate::vms::Freshness::Stale;
    // The creation hook is keyed on what is materialized, not on the plan, so it can be due
    // to run again with nothing in the plan having moved at all.
    let create_pending = plan.hooks.create.is_some()
        && !stamped(
            plan,
            "create",
            &generation_of(plan, &root_identity(plan, &vm)),
        );
    let pending = "create hook will run again on the next boot\n";
    let mut out = String::new();
    if groups.is_empty() && !stale {
        out.push_str(&format!(
            "the running environment matches the plan ({})\n",
            &digest[..12]
        ));
        if create_pending {
            out.push_str(pending);
        }
        out.push_str(&crate::dev::storage::preview(plan));
        return Ok(Some(out));
    }
    for (effect, lines) in &groups {
        out.push_str(&format!("{}:\n", effect.describe()));
        for l in lines {
            out.push_str(&format!("  {l}\n"));
        }
    }
    if stale {
        out.push_str(&format!(
            "{}:\n  the image's sources have changed since it was built\n",
            Effect::Rebuild.describe()
        ));
    }
    if create_pending {
        out.push_str(pending);
    }
    if !stale && applied_on_attach(&groups) {
        out.push_str("`vk dev up` applies all of it, without a restart\n");
    } else {
        out.push_str("`vk dev refresh` applies all of it\n");
    }
    out.push_str(&crate::dev::storage::preview(plan));
    Ok(Some(out))
}

/// The differences between two manifests, one line each, grouped by what applying them
/// takes. Empty when they are the same.
pub(super) fn drift(
    recorded: &serde_json::Value,
    current: &serde_json::Value,
) -> std::collections::BTreeMap<Effect, Vec<String>> {
    let mut before = std::collections::BTreeMap::new();
    flatten(recorded, "", &mut before);
    let mut after = std::collections::BTreeMap::new();
    flatten(current, "", &mut after);
    let mut groups: std::collections::BTreeMap<Effect, Vec<String>> = Default::default();
    for key in before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        // A fingerprint stands for a value this host supplied, so the key is all a diff
        // says about it: printing the digests would say no more and read like a secret.
        let hidden =
            |v: Option<&String>| v.is_some_and(|v| v.starts_with(&format!("\"{FINGERPRINT}")));
        let line = match (before.get(key), after.get(key)) {
            (Some(a), Some(b)) if a == b => continue,
            _ if hidden(before.get(key)) || hidden(after.get(key)) => {
                format!("{key}: changed (a value this host supplies)")
            }
            (Some(a), Some(b)) => format!("{key}: {a} -> {b}"),
            (Some(a), None) => format!("{key}: {a} -> (removed)"),
            (None, Some(b)) => format!("{key}: (added) {b}"),
            (None, None) => continue,
        };
        groups.entry(effect_of(key)).or_default().push(line);
    }
    groups
}

/// Whether a non-empty drift is all session-level or host-side — what `up` applies to a
/// running environment without a restart.
pub(super) fn applied_on_attach(groups: &std::collections::BTreeMap<Effect, Vec<String>>) -> bool {
    !groups.is_empty()
        && groups
            .keys()
            .all(|e| matches!(e, Effect::Session | Effect::Host))
}

/// What a difference between the plan and the running environment takes to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Effect {
    Session,
    Host,
    Restart,
    Rebuild,
}

impl Effect {
    fn describe(self) -> &'static str {
        match self {
            Effect::Session => "session-only (the next exec, shell or editor session picks it up)",
            Effect::Host => "host-side (applied by the next up or attach, without a restart)",
            Effect::Restart => "restart-required",
            Effect::Rebuild => "image rebuild",
        }
    }
}

/// Which effect a manifest key has. The manifest is the plan's JSON, so the keys are the
/// plan's fields. Endpoints are republished and requirements rechecked on every attach;
/// hooks run at a start and managed directories are mounted at a boot, so those two need
/// the restart they are classified under. What only a build reads — the cache it is aimed
/// at, the target it falls back to — is a rebuild, not a restart, and an `${localEnv:…}`
/// that has become available since the boot is picked up by the next session along with the
/// value it fills in.
fn effect_of(key: &str) -> Effect {
    let top = key.split(['.', '[']).next().unwrap_or(key);
    match top {
        "exec_env" | "vscode" | "freshness" | "config" | "environment" | "tasks" | "unresolved" => {
            Effect::Session
        }
        "endpoints" | "requires" => Effect::Host,
        "cache" | "cached_only" | "fallback_target" => Effect::Rebuild,
        "source" if key.starts_with("source.Build") => Effect::Rebuild,
        _ => Effect::Restart,
    }
}

/// The manifest as `path -> value` leaves, so two of them compare entry by entry. Arrays of
/// named objects (the environment scopes, the endpoints) are keyed by name, arrays of
/// scalars (the mounts) by their value, so a reordering is not a change and an addition
/// names what was added.
fn flatten(
    v: &serde_json::Value,
    path: &str,
    out: &mut std::collections::BTreeMap<String, String>,
) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let p = match path.is_empty() {
                    true => k.clone(),
                    false => format!("{path}.{k}"),
                };
                flatten(v, &p, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                match item {
                    serde_json::Value::Object(o)
                        if o.get("name").is_some_and(|n| n.is_string()) =>
                    {
                        let name = o["name"].as_str().unwrap_or_default();
                        let mut rest = o.clone();
                        rest.remove("name");
                        flatten(
                            &serde_json::Value::Object(rest),
                            &format!("{path}.{name}"),
                            out,
                        );
                    }
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        flatten(item, &format!("{path}[{i}]"), out)
                    }
                    scalar => {
                        out.insert(format!("{path}[{scalar}]"), "present".into());
                    }
                }
            }
        }
        scalar => {
            out.insert(path.to_string(), scalar.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::boot::ensure_state_dir;
    use crate::dev::config::Freshness;
    use crate::dev::plan::EnvVar;
    use crate::dev::testutil::{env_guard, mount, plan_in, scratch, shell};

    /// A marker for `vm`, as `after_boot` leaves it for `plan` when its readying fails.
    fn left_for(plan: &Plan, vm: VmTie) -> NotReady {
        let (digest, manifest) = identity_of(plan, None).unwrap();
        NotReady {
            vm,
            digest,
            manifest,
            booted_secs: 1000,
            readier: None,
            why: "hooks.start: exited with 1".into(),
        }
    }

    #[test]
    fn a_marker_is_taken_over_once_nobody_readies_it_and_by_one_caller() {
        let t = scratch("not-ready");
        let plan = plan_in(&t.0);
        std::fs::create_dir_all(&plan.state_dir).unwrap();
        let vm = VmTie {
            pid: 41,
            created_secs: 7,
        };
        let pid = std::process::id();
        let me = Readier::of(pid).expect("this process has a start time");
        // Nothing marked: a boot in flight is waited for, not taken over.
        assert!(read_not_ready(&plan).is_none());
        assert!(claim_not_ready(&plan, pid, |_| true).is_none());

        // A live readier is a boot in flight; one whose pid now runs another process, or
        // none (its readying failed), has left the VM to whoever claims it.
        let mut left = left_for(&plan, vm);
        left.readier = Some(me);
        assert!(!left.abandoned());
        mark_not_ready(&plan, &left);
        assert!(claim_not_ready(&plan, pid, |_| true).is_none());
        assert_eq!(
            read_not_ready(&plan).unwrap().readier,
            Some(me),
            "left as it was"
        );
        left.readier = Some(Readier {
            pid,
            started: me.started + 1,
        });
        assert!(left.abandoned());
        left.readier = None;
        assert!(left.abandoned());
        // Naming nobody without a failure says nothing about who readies it: not taken.
        left.why.clear();
        assert!(!left.abandoned());
        left.why = "hooks.start: exited with 1".into();

        mark_not_ready(&plan, &left);
        assert!(
            claim_not_ready(&plan, pid, |_| false).is_none(),
            "a marker that no longer passes is not taken"
        );
        let taken = claim_not_ready(&plan, pid, |_| true).expect("it was put back");
        assert_eq!((taken.booted_secs, taken.readier), (1000, Some(me)));
        assert_eq!(
            taken.why, "hooks.start: exited with 1",
            "for the claimer to report"
        );
        let now = read_not_ready(&plan).unwrap();
        assert_eq!(
            (now.readier, now.why.as_str()),
            (Some(me), ""),
            "back where joiners look, naming the claimer's parent and no failure"
        );
        assert!(
            claim_not_ready(&plan, pid, |_| true).is_none(),
            "and only the first caller takes it over"
        );
        // A parent procfs cannot name is never made the readier.
        mark_not_ready(&plan, &left);
        assert!(claim_not_ready(&plan, NO_PID, |_| true).is_none());
        assert_eq!(read_not_ready(&plan).unwrap().readier, None);

        // The parent finds what was claimed for it, for the VM it readies only, and drops
        // the marker once ready — not one naming another readier.
        let other = VmTie {
            pid: 42,
            created_secs: 7,
        };
        claim_not_ready(&plan, pid, |_| true).unwrap();
        assert!(claimed_for_me(&plan, Some(other)).is_none());
        assert_eq!(claimed_for_me(&plan, Some(vm)).unwrap().vm, vm);
        drop_own_not_ready(&plan);
        assert!(read_not_ready(&plan).is_none());
        mark_not_ready(&plan, &left);
        drop_own_not_ready(&plan);
        assert!(read_not_ready(&plan).is_some(), "not this parent's to drop");

        // A new boot drops the marker.
        clear_not_ready(&plan);
        assert!(read_not_ready(&plan).is_none());
    }

    /// A pid no process has: pids stay below `pid_max`, which is at most 2^22.
    const NO_PID: u32 = 1 << 22;

    #[test]
    fn a_process_that_is_gone_is_nobody_to_wait_on() {
        // No readier to name, and a marker naming a process that has gone is abandoned.
        assert_eq!(Readier::of(NO_PID), None);
        let t = scratch("gone-readier");
        let plan = plan_in(&t.0);
        let mut left = left_for(
            &plan,
            VmTie {
                pid: 41,
                created_secs: 7,
            },
        );
        left.why.clear();
        left.readier = Some(Readier {
            pid: NO_PID,
            started: 1,
        });
        assert!(left.abandoned());
        assert_eq!(left.reason(), "the process readying it is gone");
    }

    #[test]
    fn a_claim_waits_for_whoever_is_rewriting_the_marker() {
        let _env = env_guard();
        let t = scratch("not-ready-lock");
        let plan = plan_in(&t.0);
        std::fs::create_dir_all(&plan.state_dir).unwrap();
        let pid = std::process::id();
        let mut left = left_for(
            &plan,
            VmTie {
                pid: 41,
                created_secs: 7,
            },
        );
        left.readier = Some(Readier {
            pid,
            started: Readier::of(pid).unwrap().started + 1,
        });
        mark_not_ready(&plan, &left);
        // A readier updating the marker holds the lock across its read and write; a claim
        // meanwhile waits and then sees what it wrote — here, a live readier.
        let held = lock_not_ready(&plan).unwrap();
        std::thread::scope(|s| {
            let claim = s.spawn(|| claim_not_ready(&plan, pid, |_| true));
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(!claim.is_finished(), "the claim waits for the lock");
            left.readier = Readier::of(pid);
            write_not_ready(&plan, &left).unwrap();
            drop(held);
            assert!(claim.join().unwrap().is_none(), "the readier is alive");
        });
    }

    #[test]
    fn only_the_vm_a_marker_names_is_taken_over_and_only_from_its_config() {
        let t = scratch("left-behind");
        let mut plan = plan_in(&t.0);
        plan.exec_env = vec![EnvVar {
            name: "A".into(),
            value: "one".into(),
            sensitive: false,
        }];
        let vm = VmTie {
            pid: 41,
            created_secs: 7,
        };
        let left = left_for(&plan, vm);
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        assert_eq!(
            left_behind(&left, Some(vm), &digest, &manifest),
            Some(LeftBehind::Claim)
        );
        // Another VM is up — the one a later boot put in place, or the same pid refiled —
        // or none is: the marker describes nothing that is running.
        let later = VmTie {
            pid: 41,
            created_secs: 8,
        };
        assert_eq!(left_behind(&left, Some(later), &digest, &manifest), None);
        assert_eq!(left_behind(&left, None, &digest, &manifest), None);
        // A change readying applies is no obstacle; one that takes a restart is drift.
        let mut session = plan.clone();
        session.exec_env[0].value = "two".into();
        let (digest, manifest) = identity_of(&session, None).unwrap();
        assert_eq!(
            left_behind(&left, Some(vm), &digest, &manifest),
            Some(LeftBehind::Claim)
        );
        let mut restart = plan.clone();
        restart.mem = Some("16G".into());
        let (digest, manifest) = identity_of(&restart, None).unwrap();
        assert_eq!(
            left_behind(&left, Some(vm), &digest, &manifest),
            Some(LeftBehind::Drifted)
        );
    }

    #[test]
    fn the_identity_fingerprints_secrets_instead_of_recording_them() {
        let t = scratch("identity");
        let mut plan = plan_in(&t.0);
        plan.exec_env = vec![EnvVar {
            name: "TOKEN".into(),
            value: "s3cret".into(),
            sensitive: true,
        }];
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let text = serde_json::to_string(&manifest).unwrap();
        assert!(
            !text.contains("s3cret"),
            "the manifest is written to disk: {text}"
        );
        assert!(text.contains("sha256:"), "{text}");

        // A changed secret is still drift, even though its value is never stored.
        plan.exec_env[0].value = "other".into();
        let (changed, _) = identity_of(&plan, None).unwrap();
        assert_ne!(digest, changed);
    }

    #[test]
    fn the_digest_is_stable_for_the_same_plan() {
        let t = scratch("identity-stable");
        let mut plan = plan_in(&t.0);
        plan.secrets = ["tok".to_string()].into_iter().collect();
        plan.exec_env = vec![EnvVar {
            name: "T".into(),
            value: "tok".into(),
            sensitive: true,
        }];
        assert_eq!(
            identity_of(&plan, None).unwrap().0,
            identity_of(&plan, None).unwrap().0
        );
    }

    #[test]
    fn a_value_this_host_supplied_is_fingerprinted_wherever_it_landed() {
        let t = scratch("identity-secrets");
        let mut plan = plan_in(&t.0);
        // `${localEnv:…}` expands in more than the two environment scopes: what it fed a
        // mount source, a build argument and a task's environment is written down too.
        plan.secrets = ["s3cret".to_string()].into_iter().collect();
        // Every one of these only *contains* the secret, embedded in a larger string — the
        // case exact-equality missed and wrote to disk verbatim.
        plan.mounts = vec![mount("cache", "/opt/s3cret/cache", "/c")];
        plan.tasks = vec![crate::dev::plan::TaskPlan {
            name: "build".into(),
            argv: vec!["true".into()],
            environment: "dev".into(),
            reuse: "dev".into(),
            policy: crate::dev::config::Policy::Ephemeral,
            checkout: crate::dev::config::CheckoutMode::Shared,
            env: vec![EnvVar {
                name: "DATABASE_URL".into(),
                value: "postgres://u:s3cret@h/db".into(),
                sensitive: true,
            }],
        }];
        plan.source = Source::Build {
            context: t.0.join("repo"),
            dockerfile: t.0.join("repo/Dockerfile"),
            target: None,
            args: vec![("AUTH".into(), "Bearer s3cret".into())],
        };
        let (_, manifest) = identity_of(&plan, None).unwrap();
        let text = serde_json::to_string(&manifest).unwrap();
        // Nowhere, embedded or not — the manifest is written to disk and shown by `--diff`.
        assert!(!text.contains("s3cret"), "{text}");
        // The surrounding text stays, so drift is still legible.
        assert!(text.contains("Bearer sha256:"), "{text}");
        assert!(text.contains("/opt/sha256:"), "{text}");

        // A diff over it names the key and nothing else — not even the digests.
        let mut after = plan.clone();
        after.tasks[0].env[0].value = "other".into();
        after.secrets.insert("other".into());
        let (_, changed) = identity_of(&after, None).unwrap();
        let lines: Vec<String> = drift(&manifest, &changed).into_values().flatten().collect();
        assert_eq!(
            lines,
            ["tasks.build.env.DATABASE_URL.value: changed (a value this host supplies)"]
        );
    }

    #[test]
    fn the_identity_covers_the_host_command_allowlist() {
        let t = scratch("identity-wrapper");
        let plan = plan_in(&t.0);
        let (a, _) = identity_of(&plan, Some("aaa")).unwrap();
        let (b, _) = identity_of(&plan, Some("bbb")).unwrap();
        assert_ne!(a, b, "a changed allowlist is a changed environment");
    }

    #[test]
    fn the_generation_follows_the_image_the_storage_and_the_hook() {
        let t = scratch("generation");
        let mut plan = plan_in(&t.0);
        let store = plan.state_dir.join("store");
        plan.managed_dirs = vec![store.clone()];
        plan.hooks.create = Some(shell("setup.sh"));
        ensure_state_dir(&plan).unwrap();
        let base = generation_of(&plan, "ext4:aaaa");

        // A rebuilt image stamps another UUID into the root filesystem.
        assert_ne!(base, generation_of(&plan, "ext4:bbbb"));

        // A config key the creation hook never sees is not a new generation.
        let mut unrelated = plan.clone();
        unrelated.mem = Some("8G".into());
        unrelated.freshness = Freshness::Reuse;
        assert_eq!(base, generation_of(&unrelated, "ext4:aaaa"));

        // Editing what the hook runs does run it again.
        let mut edited = plan.clone();
        edited.hooks.create = Some(shell("setup.sh --more"));
        assert_ne!(base, generation_of(&edited, "ext4:aaaa"));

        // `vk dev storage reset` removes the directory; the next boot recreates it with
        // another token, so what populated it runs again.
        std::fs::remove_dir_all(&store).unwrap();
        ensure_state_dir(&plan).unwrap();
        assert_ne!(base, generation_of(&plan, "ext4:aaaa"));
    }

    #[test]
    fn a_diff_names_each_change_by_what_it_takes_to_apply() {
        let t = scratch("diff");
        let mut a = plan_in(&t.0);
        a.exec_env = vec![EnvVar {
            name: "TOKEN".into(),
            value: "one".into(),
            sensitive: true,
        }];
        a.mounts = vec![mount("a", "/a", "/a"), mount("b", "/b", "/b")];
        let (_, before) = identity_of(&a, None).unwrap();
        let mut b = a.clone();
        b.exec_env[0].value = "two".into();
        b.mounts = vec![mount("b", "/b", "/b"), mount("c", "/c", "/c")];
        b.mem = Some("8G".into());
        b.hooks.start = Some(shell("true"));
        b.source = Source::Build {
            context: t.0.join("repo"),
            dockerfile: t.0.join("repo/Dockerfile"),
            target: None,
            args: Vec::new(),
        };
        let (_, after) = identity_of(&b, None).unwrap();
        let effects: std::collections::BTreeMap<String, Effect> = drift(&before, &after)
            .into_iter()
            .flat_map(|(effect, lines)| {
                lines.into_iter().map(move |l| {
                    let key = l.split_once(": ").map(|(k, _)| k.to_string()).unwrap();
                    (key, effect)
                })
            })
            .collect();
        // Only the token changing is a drift new sessions absorb; nothing to restart for.
        let mut c = a.clone();
        c.exec_env[0].value = "two".into();
        let (_, only_env) = identity_of(&c, None).unwrap();
        let groups = drift(&before, &only_env);
        assert!(groups.keys().all(|e| *e == Effect::Session), "{groups:?}");
        assert!(drift(&before, &before).is_empty());
        // A secret's value is fingerprinted, so a changed one still shows — as session-only.
        assert_eq!(effects["exec_env.TOKEN.value"], Effect::Session);
        // A mount is keyed by its name, so reordering is nothing; a new one is a restart.
        assert!(!effects.contains_key("mounts.b.source"), "{effects:?}");
        assert_eq!(effects["mounts.c.source"], Effect::Restart);
        assert_eq!(effects["mounts.a.source"], Effect::Restart);
        assert_eq!(effects["mem"], Effect::Restart);
        assert_eq!(effects["hooks.start.Command.run"], Effect::Restart);
        assert_eq!(effect_of("endpoints[\"web\"].host_port"), Effect::Host);
        assert_eq!(effect_of("managed_dirs[\"/s/data\"]"), Effect::Restart);
        // Endpoint-only drift is applied by attaching; a hook change is not.
        let mut d = std::collections::BTreeMap::new();
        d.insert(Effect::Host, vec!["endpoints".to_string()]);
        assert!(applied_on_attach(&d));
        d.insert(Effect::Restart, vec!["hooks".to_string()]);
        assert!(!applied_on_attach(&d));
        assert_eq!(effects["source.Build.context"], Effect::Rebuild);
        assert!(!effects.contains_key("user"), "unchanged: {effects:?}");
        // A `${localEnv:…}` that has become available is picked up by the next session,
        // together with the value it fills in — not a reason to restart.
        assert_eq!(
            effect_of("unresolved[\"${localEnv:TOKEN}\"]"),
            Effect::Session
        );
        // What only a build reads is a rebuild, not a restart.
        assert_eq!(effect_of("cache.registry"), Effect::Rebuild);
        assert_eq!(effect_of("cached_only"), Effect::Rebuild);
        assert_eq!(effect_of("fallback_target"), Effect::Rebuild);
    }

    #[test]
    fn an_older_creator_is_named_and_a_current_or_odd_one_is_not() {
        assert_eq!(older_creator("vk 0.1.0 (abc)"), Some("0.1.0".into()));
        assert_eq!(older_creator(&own_version()), None);
        assert_eq!(older_creator("vk 999.0.0 (dev)"), None);
        assert_eq!(older_creator(""), None);
        assert_eq!(older_creator("something else"), None);
    }
}
