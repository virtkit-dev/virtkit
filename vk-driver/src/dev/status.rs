//! What `vk dev status` and `vk dev doctor` report, without changing anything.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use crate::dev::plan::{Plan, Source};

use super::boot::{alias, worktree_git_dir};
use super::hooks::{check_requirements, stamped};
use super::identity::{
    LeftBehind, NotReady, VmTie, applied_on_attach, drift, generation_of, identity_of, left_behind,
    read_identity, read_not_ready, root_identity, wrapper_digest,
};
use super::session::running_vm;

/// `vk dev status`: whether the environment is up, and whether it still matches its config.
/// One record, rendered as text or `--json`, so a script reads the same facts a person does.
#[derive(Debug, Serialize)]
pub struct Status {
    pub workspace: PathBuf,
    pub config: PathBuf,
    pub environment: String,
    pub source: String,
    pub state_dir: PathBuf,
    pub running: bool,
    pub pid: Option<u32>,
    /// how the config compares with the recorded identity, when running
    pub config_state: Option<ConfigState>,
    /// readiness from the not-ready marker, for a running environment with no identity
    pub not_ready: Option<NotReadyState>,
    pub booted_digest: Option<String>,
    pub current_digest: String,
    /// how the running images compare with the sources they were built from
    pub image: Option<ImageState>,
    pub freshness: &'static str,
    pub ssh_alias: String,
    pub ssh_config: PathBuf,
    pub published: Vec<Published>,
    /// the durable storage items that exist, by name — what a refresh or a stop keeps
    pub storage: Vec<String>,
    /// `${localEnv:…}` this shell could not fill
    pub unresolved: Vec<String>,
    /// the `vk` that booted what is running, when it recorded one
    pub created_by: Option<String>,
    /// what is running as materialized — image and managed-storage identity, and the
    /// creation hook's own command
    pub generation: Option<String>,
    /// whether `hooks.create` runs again on the next boot: it is configured, and what is
    /// running was not initialized for this generation
    pub create_hook_pending: bool,
}

/// How the config compares with what the running environment was booted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigState {
    /// the same plan, digest for digest
    Matches,
    /// changed only in what an attach applies — no restart needed
    SessionOnly,
    /// changed in something the running VM cannot be told about
    Drifted,
    /// running, but nothing was recorded to compare against
    Unknown,
}

/// Why a running environment is not ready, from its VM's not-ready marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum NotReadyState {
    /// a parent is readying it now; `vk dev` waits for that
    Readying { pid: u32 },
    /// its readying failed or its parent is gone: the next `vk dev` command takes it over,
    /// or, when `drifted` (booted from a different configuration), the freshness policy
    /// decides
    Abandoned { reason: String, drifted: bool },
}

/// Interpret `left` for `running` and the current `digest`/`manifest`, as a joiner does.
/// Return `None` for another VM's marker, or one with neither a readier nor a failure.
fn not_ready_state(
    left: &NotReady,
    running: VmTie,
    digest: &str,
    manifest: &serde_json::Value,
) -> Option<NotReadyState> {
    let how = left_behind(left, Some(running), digest, manifest)?;
    match (left.abandoned(), left.readier) {
        (true, _) => Some(NotReadyState::Abandoned {
            reason: left.reason().to_string(),
            drifted: how == LeftBehind::Drifted,
        }),
        (false, Some(r)) => Some(NotReadyState::Readying { pid: r.pid }),
        (false, None) => None,
    }
}

/// How a running environment's images compare with the sources they were built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageState {
    Fresh,
    Stale,
    Unknown,
}

/// One live publisher, as `vk dev status` reports it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Published {
    /// the host address it listens on
    pub listen: String,
    /// what it forwards to in the guest
    pub to: String,
}

pub fn status(plan: &Plan) -> Result<Status> {
    let (current_digest, manifest) = identity_of(plan, wrapper_digest(plan).as_deref())?;
    let vm = running_vm(plan);
    let recorded = vm.as_ref().and_then(|_| read_identity(plan));
    // Without an identity, a marker naming this VM distinguishes a boot in progress
    // from one left not ready.
    let left = match (&vm, &recorded) {
        (Some(vm), None) => read_not_ready(plan).and_then(|left| {
            let state = not_ready_state(&left, VmTie::of(vm), &current_digest, &manifest)?;
            Some((left, state))
        }),
        _ => None,
    };
    // Use the boot configuration from the identity, falling back to the not-ready marker.
    let booted = recorded
        .as_ref()
        .map(|id| (&id.digest, &id.manifest))
        .or(left
            .as_ref()
            .map(|(left, _)| (&left.digest, &left.manifest)));
    let config_state = vm.as_ref().map(|_| match booted {
        Some((digest, _)) if *digest == current_digest => ConfigState::Matches,
        // What `up` applies to a running environment is not drift worth a restart.
        Some((_, booted)) if applied_on_attach(&drift(booted, &manifest)) => {
            ConfigState::SessionOnly
        }
        Some(_) => ConfigState::Drifted,
        None => ConfigState::Unknown,
    });
    let booted_digest = booted.map(|(digest, _)| digest.clone());
    // Whether the config matches is one question; whether the images it names still match
    // their sources is another, and a caller deciding whether to refresh wants both.
    let image = vm.as_ref().map(|vm| match crate::vms::freshness_all(vm) {
        crate::vms::Freshness::Stale => ImageState::Stale,
        crate::vms::Freshness::Fresh => ImageState::Fresh,
        crate::vms::Freshness::Unknown => ImageState::Unknown,
    });
    // What the creation hook was run for, against what is materialized now: a rebuilt image
    // or a reset directory has it run again on the next boot, and a caller weighing a
    // refresh wants to know that before it happens.
    let generation = vm
        .as_ref()
        .map(|vm| generation_of(plan, &root_identity(plan, vm)));
    let create_hook_pending = plan.hooks.create.is_some()
        && generation
            .as_deref()
            .is_some_and(|g| !stamped(plan, "create", g));
    // Every other optional source here degrades rather than failing the report; a publisher
    // registry that cannot be read is no reason for `vk dev status` to say nothing at all.
    let published: Vec<Published> = match vm {
        Some(_) => crate::publish::live(&plan.state_dir)
            .unwrap_or_default()
            .into_iter()
            .map(|(p, _)| Published {
                listen: p.listen,
                to: p.to,
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(Status {
        workspace: plan.workspace.clone(),
        config: plan.config.clone(),
        environment: plan.environment.clone(),
        source: describe_source(&plan.source),
        state_dir: plan.state_dir.clone(),
        running: vm.is_some(),
        pid: vm.as_ref().map(|vm| vm.pid),
        config_state,
        not_ready: left.map(|(_, state)| state),
        created_by: recorded
            .as_ref()
            .map(|id| id.created_by.clone())
            .filter(|v| !v.is_empty()),
        booted_digest,
        current_digest,
        generation,
        create_hook_pending,
        image,
        freshness: plan.freshness.as_str(),
        ssh_alias: alias(plan),
        ssh_config: plan.state_dir.join(crate::sshclient::CONFIG),
        published,
        // Read storage names from Compose and the config's mounts without measuring them.
        // Keep status available even when the source cannot be read.
        storage: crate::dev::storage::inventory(plan, false)
            .unwrap_or_default()
            .into_iter()
            .filter(|i| i.exists && i.category == crate::dev::storage::Category::Durable)
            .map(|i| i.name)
            .collect(),
        unresolved: plan.unresolved.clone(),
    })
}

fn describe_source(source: &Source) -> String {
    match source {
        Source::Compose { file, service, .. } => format!("{} service {service}", file.display()),
        Source::Image { reference } => format!("image {reference}"),
        Source::Build {
            dockerfile, target, ..
        } => format!(
            "{}{}",
            dockerfile.display(),
            target
                .as_deref()
                .map(|t| format!(" target {t}"))
                .unwrap_or_default()
        ),
    }
}

impl Status {
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut line = |k: &str, v: String| out.push_str(&format!("{k:<12}{v}\n"));
        line("workspace", self.workspace.display().to_string());
        line(
            "config",
            format!("{} [{}]", self.config.display(), self.environment),
        );
        line("source", self.source.clone());
        line("state", self.state_dir.display().to_string());
        if !self.storage.is_empty() {
            line("storage", self.storage.join(", "));
        }
        let Some(pid) = self.pid else {
            line("status", "not running".into());
            for u in &self.unresolved {
                line("unresolved", u.clone());
            }
            return out;
        };
        line("status", format!("running (pid {pid})"));
        match &self.not_ready {
            Some(NotReadyState::Readying { pid }) => line(
                "ready",
                format!("not yet: being readied by pid {pid}; `vk dev` waits for it"),
            ),
            Some(NotReadyState::Abandoned { reason, drifted }) => line(
                "ready",
                format!(
                    "no: its readying did not finish ({reason}); {}",
                    match drifted {
                        false => "the next `vk dev` command takes it over",
                        true => "the freshness policy decides on the next `vk dev` command",
                    }
                ),
            ),
            None => {}
        }
        if let Some(by) = &self.created_by {
            line("created by", by.clone());
        }
        let short = |d: &str| d.chars().take(12).collect::<String>();
        if let Some(generation) = &self.generation {
            line(
                "generation",
                match self.create_hook_pending {
                    true => format!("{} — create hook will run again", short(generation)),
                    false => short(generation),
                },
            );
        }
        line(
            "config",
            match (self.config_state, &self.booted_digest) {
                (Some(ConfigState::Matches), _) => "matches what is running".into(),
                (Some(ConfigState::SessionOnly), _) => {
                    "changed since the boot only in what attaching applies (exec-env, editor, \
                     endpoints, tasks); `vk dev up` applies it, no restart needed"
                        .into()
                }
                (Some(ConfigState::Drifted), Some(booted)) => format!(
                    "DRIFTED: booted from {}, now {} — `vk dev refresh` (freshness: {})",
                    short(booted),
                    short(&self.current_digest),
                    self.freshness
                ),
                (Some(ConfigState::Drifted | ConfigState::Unknown) | None, _) => {
                    "unknown: nothing recorded for this environment".into()
                }
            },
        );
        line(
            "image",
            match self.image {
                Some(ImageState::Stale) => "stale: the sources have changed since it was built",
                Some(ImageState::Fresh) => "matches the sources it was built from",
                Some(ImageState::Unknown) | None => "unknown",
            }
            .into(),
        );
        line(
            "ssh",
            format!(
                "vk dev ssh, or ssh -F {} {}",
                self.ssh_config.display(),
                self.ssh_alias
            ),
        );
        for p in &self.published {
            line("published", format!("{} -> {}", p.listen, p.to));
        }
        for u in &self.unresolved {
            line("unresolved", u.clone());
        }
        out
    }
}

/// `vk dev doctor`: whether this host can run the environment, one line per check. Nothing
/// is changed; a failing line says what to do. Returns the report and whether every check
/// passed.
pub fn doctor(plan: &Plan, cfg: &crate::config::Config) -> (String, bool) {
    let mut out = String::new();
    let mut all_ok = true;
    let mut line = |ok: bool, name: &str, detail: String| {
        all_ok &= ok;
        out.push_str(&format!(
            "{:<4} {name:<10} {detail}\n",
            if ok { "ok" } else { "FAIL" }
        ));
    };
    // What the config requires of this build, and the host capabilities a boot needs.
    match check_requirements(plan, cfg) {
        Ok(()) => line(
            true,
            "requires",
            "this vk satisfies the config's requirements".into(),
        ),
        Err(e) => line(false, "requires", format!("{e:#}")),
    }
    for f in [
        crate::check::Feature::Kvm,
        crate::check::Feature::Vmm,
        crate::check::Feature::Kernel,
    ] {
        match crate::check::probe(cfg, f) {
            Ok(()) => line(true, "host", format!("{f:?} available").to_lowercase()),
            Err(why) => line(false, "host", why),
        }
    }
    match plan.nested {
        crate::dev::config::Nested::Off => {}
        crate::dev::config::Nested::Required => match crate::vmm::host_nesting_enabled() {
            true => line(true, "host", "nested virtualization enabled".into()),
            false => line(
                false,
                "host",
                "nested virtualization is not enabled (the kvm_intel/kvm_amd `nested` \
                 module parameter), and the config requires it"
                    .into(),
            ),
        },
        // Reports the config's own `nested` only. A compose service can still force nesting
        // with `x-virtkit.nested = true`, which is not resolved here, so a boot may be refused
        // on a host without it even when this line passes.
        crate::dev::config::Nested::Auto => line(
            true,
            "host",
            match crate::vmm::host_nesting_enabled() {
                true => "nested virtualization enabled".into(),
                false => {
                    "nested virtualization not enabled: the environment runs without it".into()
                }
            },
        ),
    }
    // Tools the daily commands shell out to.
    for tool in ["ssh", "git"] {
        match crate::shell::which(tool) {
            Some(p) => line(true, "tool", format!("{tool}: {}", p.display())),
            None => line(false, "tool", format!("{tool} is not on PATH")),
        }
    }
    match crate::dev::editor::EDITORS
        .iter()
        .find_map(|e| crate::shell::which(e))
    {
        Some(p) => line(true, "editor", p.display().to_string()),
        None => line(
            true,
            "editor",
            "no VS Code on PATH; `vk dev code --editor` names one".into(),
        ),
    }
    // The source and mounts this host has to supply.
    match &plan.source {
        Source::Compose { file, .. } => line(
            file.is_file(),
            "source",
            format!("compose file {}", file.display()),
        ),
        Source::Image { reference } => line(true, "source", format!("image {reference}")),
        Source::Build { dockerfile, .. } => line(
            dockerfile.is_file(),
            "source",
            format!("Dockerfile {}", dockerfile.display()),
        ),
    }
    // What the guest may ask the host to run. A built-in policy is this binary, so there is
    // nothing on disk to check; a project wrapper has to be there and be executable.
    match &plan.host_exec {
        None => {}
        Some(h) => match &h.builtin {
            Some(policy) => line(true, "host", format!("{policy} policy (built in)")),
            None => {
                let ok = std::fs::metadata(&h.wrapper)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
                let detail = format!("host wrapper {}", h.wrapper.display());
                line(
                    ok,
                    "host",
                    match ok {
                        true => detail,
                        false => format!("{detail} is not an executable file"),
                    },
                );
            }
        },
    }
    if worktree_git_dir(&plan.workspace).is_some() {
        line(
            true,
            "git",
            "linked worktree: its common directory will be mounted".into(),
        );
    }
    for m in &plan.mounts {
        // Managed storage is created at boot, and reported as such below.
        if plan.managed_dirs.contains(&m.source) {
            continue;
        }
        let host = m.source.display();
        let readable = std::fs::metadata(&m.source).is_ok();
        match (readable, m.optional) {
            (true, _) => line(true, "mount", format!("{host} readable")),
            (false, true) => line(true, "mount", format!("{host} absent, optional: skipped")),
            (false, false) => line(false, "mount", format!("{host} is not readable")),
        }
    }
    for dir in &plan.managed_dirs {
        line(
            true,
            "storage",
            format!("{} (managed, created at boot)", dir.display()),
        );
    }
    // Endpoints: a host port another program holds is found now, not once the VM is up.
    let running = running_vm(plan).is_some();
    let alloc = crate::dev::endpoints::load(plan).unwrap_or_else(|e| {
        eprintln!("virtkit: no endpoint address to check: {e:#}");
        None
    });
    for ep in &plan.endpoints {
        // `tcp://auto:<port>` is a placeholder. Publication allocates the address;
        // until it is remembered, there is nothing to probe.
        let Some(address) = crate::dev::endpoints::address_of(alloc.as_ref(), ep) else {
            line(
                true,
                "endpoint",
                format!(
                    "{}: 127.0.<block>.<octet>:{} (allocated when it is published)",
                    ep.name, ep.host_port
                ),
            );
            continue;
        };
        // A configured non-loopback address is what `publish` refuses, so doctor reports it
        // as a fault rather than binding it and calling the exposed port free.
        if let Err(e) = crate::dev::endpoints::require_bindable(&ep.name, &address) {
            line(false, "endpoint", format!("{e:#}"));
            continue;
        }
        let addr = crate::dev::endpoints::authority(&address, ep.host_port);
        if running {
            line(
                true,
                "endpoint",
                format!("{}: {addr} (environment running)", ep.name),
            );
            continue;
        }
        match std::net::TcpListener::bind(&*addr) {
            Ok(_) => line(true, "endpoint", format!("{}: {addr} is free", ep.name)),
            Err(e) => line(
                !ep.required,
                "endpoint",
                format!(
                    "{}: cannot bind {addr} ({e}){}",
                    ep.name,
                    if ep.required { "" } else { " — optional" }
                ),
            ),
        }
    }
    // The state dir must be creatable, and what lands in it must not be reachable by the
    // guest — the plan already refused that.
    let state_parent = plan
        .state_dir
        .ancestors()
        .find(|p| p.exists())
        .map(Path::to_path_buf);
    match state_parent {
        Some(p) if writable(&p) => line(true, "state", plan.state_dir.display().to_string()),
        _ => line(
            false,
            "state",
            format!("{} cannot be created", plan.state_dir.display()),
        ),
    }
    for u in &plan.unresolved {
        line(false, "env", u.clone());
    }
    (out, all_ok)
}

/// Whether *this* user may write `dir` — the mode bits alone say nothing about that, and a
/// state directory the caller cannot create is the finding worth reporting.
fn writable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a NUL-terminated path this call only reads; it returns 0 or -1. `AT_EACCESS`
    // asks about the effective ids, which is what a write from this process would use.
    unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::W_OK, libc::AT_EACCESS) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::identity::Readier;
    use crate::dev::testutil::{mount, plan_in, scratch};

    #[test]
    fn status_and_doctor_read_an_absent_environment_without_booting_it() {
        let t = scratch("status");
        let mut plan = plan_in(&t.0);
        plan.unresolved = vec!["${localEnv:TOKEN} is not set".into()];
        plan.mounts = vec![
            crate::dev::plan::MountPlan {
                read_only: true,
                optional: true,
                ..mount("absent", t.0.join("absent"), "/a")
            },
            mount("missing", t.0.join("missing"), "/b"),
            mount("store", t.0.join("state/store"), "/c"),
        ];
        plan.managed_dirs = vec![t.0.join("state/store")];
        let s = status(&plan).unwrap();
        assert!(!s.running && s.pid.is_none() && s.config_state.is_none());
        assert_eq!(s.environment, "dev");
        let text = s.render();
        assert!(text.contains("not running"), "{text}");
        assert!(text.contains("unresolved"), "{text}");
        let json: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(json["running"], false);
        assert_eq!(json["unresolved"][0], "${localEnv:TOKEN} is not set");

        let (report, ok) = doctor(&plan, &crate::config::Config::default());
        assert!(!ok, "{report}");
        // A missing optional source is fine; a missing required one, and an unfilled
        // variable, are not.
        assert!(report.contains("absent, optional"), "{report}");
        assert!(
            report.contains("FAIL mount") && report.contains("/missing"),
            "{report}"
        );
        assert!(report.contains("FAIL env"), "{report}");
        // Managed storage does not exist yet either, and that is not a finding.
        assert!(
            !report.contains("store is not readable") && report.contains("ok   storage"),
            "{report}"
        );
        assert!(!t.0.join("state").exists(), "nothing was created");
    }

    #[test]
    fn a_marker_reads_as_a_joiner_reads_it() {
        let t = scratch("not-ready-state");
        let plan = plan_in(&t.0);
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let vm = VmTie {
            pid: 41,
            created_secs: 7,
        };
        let me = Readier::of(std::process::id()).unwrap();
        let left = |readier, why: &str| NotReady {
            vm,
            digest: digest.clone(),
            manifest: manifest.clone(),
            booted_secs: 1000,
            readier,
            why: why.into(),
        };
        let state = |left: &NotReady| not_ready_state(left, vm, &digest, &manifest);
        let abandoned = |reason: &str, drifted| {
            Some(NotReadyState::Abandoned {
                reason: reason.into(),
                drifted,
            })
        };
        assert_eq!(
            state(&left(Some(me), "")),
            Some(NotReadyState::Readying { pid: me.pid })
        );
        assert_eq!(
            state(&left(None, "hooks.start: exited with 1")),
            abandoned("hooks.start: exited with 1", false)
        );
        let gone = Readier {
            started: me.started + 1,
            ..me
        };
        assert_eq!(
            state(&left(Some(gone), "")),
            abandoned("the process readying it is gone", false)
        );
        // Nobody named and no failure: no joiner takes it, so it says nothing.
        assert_eq!(state(&left(None, "")), None);
        // Another VM's marker describes nothing up.
        let other = VmTie { pid: 42, ..vm };
        assert_eq!(
            not_ready_state(&left(None, "x"), other, &digest, &manifest),
            None
        );
        // Booted from another configuration: the freshness policy's to decide.
        let drifted = NotReady {
            digest: "a".repeat(64),
            manifest: serde_json::json!({}),
            ..left(None, "x")
        };
        assert_eq!(state(&drifted), abandoned("x", true));
        // A live readier is waited on, whatever it was booted from.
        let readying = NotReady {
            readier: Some(me),
            why: String::new(),
            ..drifted
        };
        assert_eq!(
            state(&readying),
            Some(NotReadyState::Readying { pid: me.pid })
        );
    }

    #[test]
    fn a_not_ready_environment_is_reported_with_what_comes_next() {
        let t = scratch("status-not-ready");
        let plan = plan_in(&t.0);
        let mut s = status(&plan).unwrap();
        assert_eq!(
            serde_json::to_value(&s).unwrap()["not_ready"],
            serde_json::Value::Null
        );
        s.pid = Some(41);
        s.running = true;
        let ready = |s: &Status| {
            s.render()
                .lines()
                .find_map(|l| l.strip_prefix("ready").map(|v| v.trim().to_string()))
        };
        assert_eq!(ready(&s), None);
        s.not_ready = Some(NotReadyState::Readying { pid: 7 });
        assert_eq!(
            ready(&s).unwrap(),
            "not yet: being readied by pid 7; `vk dev` waits for it"
        );
        assert_eq!(
            serde_json::to_value(&s).unwrap()["not_ready"],
            serde_json::json!({ "state": "readying", "pid": 7 })
        );
        s.not_ready = Some(NotReadyState::Abandoned {
            reason: "hooks.start: exited with 1".into(),
            drifted: false,
        });
        assert_eq!(
            ready(&s).unwrap(),
            "no: its readying did not finish (hooks.start: exited with 1); the next `vk dev` \
             command takes it over"
        );
        s.not_ready = Some(NotReadyState::Abandoned {
            reason: "x".into(),
            drifted: true,
        });
        assert_eq!(
            ready(&s).unwrap(),
            "no: its readying did not finish (x); the freshness policy decides on the next \
             `vk dev` command"
        );
        assert_eq!(
            serde_json::to_value(&s).unwrap()["not_ready"],
            serde_json::json!({ "state": "abandoned", "reason": "x", "drifted": true })
        );
    }

    /// For a registered VM with no identity, compare against the marker's boot configuration.
    #[test]
    fn a_not_ready_environment_is_compared_by_what_its_marker_records() {
        const CHILD: &str = "VK_TEST_STATUS_NOT_READY";
        let Some(tmp) = std::env::var_os(CHILD).map(std::path::PathBuf::from) else {
            let tmp = scratch("status-marker");
            crate::dev::testutil::in_child(
                "dev::status::tests::a_not_ready_environment_is_compared_by_what_its_marker_records",
                CHILD,
                &tmp.0,
            );
            return;
        };
        let plan = plan_in(&tmp);
        let _vm = crate::dev::testutil::register_vm(&plan);
        let (digest, manifest) = identity_of(&plan, wrapper_digest(&plan).as_deref()).unwrap();
        let mut left = NotReady {
            vm: VmTie::of(&running_vm(&plan).unwrap()),
            digest: digest.clone(),
            manifest: manifest.clone(),
            booted_secs: 1000,
            readier: None,
            why: "hooks.start: exited with 1".into(),
        };
        crate::dev::identity::mark_not_ready(&plan, &left);
        let s = status(&plan).unwrap();
        assert_eq!(s.config_state, Some(ConfigState::Matches));
        assert_eq!(s.booted_digest.as_deref(), Some(digest.as_str()));
        assert!(matches!(
            s.not_ready,
            Some(NotReadyState::Abandoned { drifted: false, .. })
        ));

        // Booted with other endpoints, which an attach applies: taken over, not drift.
        left.digest = "b".repeat(64);
        left.manifest["endpoints"] = serde_json::json!([{ "name": "web", "host_port": 8080 }]);
        crate::dev::identity::mark_not_ready(&plan, &left);
        let s = status(&plan).unwrap();
        assert_eq!(s.config_state, Some(ConfigState::SessionOnly));
        assert!(matches!(
            s.not_ready,
            Some(NotReadyState::Abandoned { drifted: false, .. })
        ));

        left.digest = "a".repeat(64);
        left.manifest = serde_json::json!({});
        crate::dev::identity::mark_not_ready(&plan, &left);
        let s = status(&plan).unwrap();
        assert_eq!(s.config_state, Some(ConfigState::Drifted));
        assert!(s.render().contains("DRIFTED: booted from aaaaaaaaaaaa"));
    }

    #[test]
    fn doctor_pre_flights_a_configured_address_and_waits_on_an_allocated_one() {
        let t = scratch("doctor-endpoints");
        let mut plan = plan_in(&t.0);
        // A `required` auto endpoint: its address is chosen by the allocator at the publish,
        // so there is nothing to bind yet — and nothing here is a reason to FAIL the host.
        plan.endpoints = vec![crate::dev::plan::EndpointPlan {
            name: "web".into(),
            service: None,
            host_port: 48082,
            address: "auto".into(),
            listen: "tcp://auto:48082".into(),
            to: "tcp://127.0.0.1:8080".into(),
            scheme: None,
            path: None,
            required: true,
        }];
        let (report, _) = doctor(&plan, &crate::config::Config::default());
        assert!(
            report.contains("ok   endpoint   web: 127.0.<block>.<octet>:48082"),
            "{report}"
        );
        assert!(!report.contains("FAIL endpoint"), "{report}");

        // A configured address is bound now, so a port something else holds is a finding.
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        plan.endpoints[0].address = "127.0.0.1".into();
        plan.endpoints[0].host_port = port;
        let (report, ok) = doctor(&plan, &crate::config::Config::default());
        assert!(!ok, "{report}");
        assert!(
            report.contains(&format!(
                "FAIL endpoint   web: cannot bind 127.0.0.1:{port}"
            )),
            "{report}"
        );
    }
}
