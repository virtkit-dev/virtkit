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
            "it was created by vk {older}; this is {} — `vk dev refresh` restarts it with \
             this one (needed when the two disagree on image or protocol formats)",
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
/// scopes: the scopes are fingerprinted by what [`crate::dev::plan::Vars`] marked, and then
/// every string anywhere in the manifest that *is* one of the values this host supplied —
/// a mount source, a build argument, a task's environment — is fingerprinted too.
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
    serde_json::Value::String(format!("{FINGERPRINT}{}", sha256_hex(value)))
}

/// The prefix every fingerprint carries.
const FINGERPRINT: &str = "sha256:";

/// Replace every string in `manifest` that is one of `secrets` with a fingerprint of it.
/// Equality, not containment: a value is a secret because this host supplied it, and a path
/// or a URL that merely has one inside it is still the config's own text.
fn fingerprint_secrets(
    manifest: &mut serde_json::Value,
    secrets: &std::collections::BTreeSet<String>,
) {
    match manifest {
        serde_json::Value::String(s) if secrets.contains(s.as_str()) => *manifest = fingerprint(s),
        serde_json::Value::Array(items) => {
            for item in items {
                fingerprint_secrets(item, secrets);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                fingerprint_secrets(value, secrets);
            }
        }
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
    use crate::dev::testutil::{mount, plan_in, scratch, shell};

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
    fn a_value_this_host_supplied_is_fingerprinted_wherever_it_landed() {
        let t = scratch("identity-secrets");
        let mut plan = plan_in(&t.0);
        // `${localEnv:…}` expands in more than the two environment scopes: what it fed a
        // mount source, a build argument and a task's environment is written down too.
        plan.secrets = ["s3cret".to_string()].into_iter().collect();
        plan.mounts = vec![mount("cache", "/opt/s3cret/cache", "/c")];
        plan.tasks = vec![crate::dev::plan::TaskPlan {
            name: "build".into(),
            argv: vec!["true".into()],
            environment: "dev".into(),
            reuse: "dev".into(),
            policy: crate::dev::config::Policy::Ephemeral,
            checkout: crate::dev::config::CheckoutMode::Shared,
            env: vec![EnvVar {
                name: "TOKEN".into(),
                value: "s3cret".into(),
                sensitive: true,
            }],
        }];
        plan.source = Source::Build {
            context: t.0.join("repo"),
            dockerfile: t.0.join("repo/Dockerfile"),
            target: None,
            args: vec![("TOKEN".into(), "s3cret".into())],
        };
        let (_, manifest) = identity_of(&plan, None).unwrap();
        let text = serde_json::to_string(&manifest).unwrap();
        assert!(!text.contains("\"s3cret\""), "{text}");
        // The mount source only *contains* the value, so it stays the config's own text.
        assert!(text.contains("\"/opt/s3cret/cache\""), "{text}");

        // A diff over it names the key and nothing else — not even the digests.
        let mut after = plan.clone();
        after.tasks[0].env[0].value = "other".into();
        after.secrets.insert("other".into());
        let (_, changed) = identity_of(&after, None).unwrap();
        let lines: Vec<String> = drift(&manifest, &changed).into_values().flatten().collect();
        assert_eq!(
            lines,
            ["tasks.build.env.TOKEN.value: changed (a value this host supplies)"]
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
