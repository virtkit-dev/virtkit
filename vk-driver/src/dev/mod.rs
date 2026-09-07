//! `vk dev`: bring up, attach to and tear down the environment a workspace's
//! `.virtkit/config.toml` describes. [`crate::dev::plan`] decides *what* the environment is;
//! this runs it, through the same `vk run` the CLI does — one boot path, not two.
//!
//! A boot is split across two processes, because `vk run --detach` is: the child boots and
//! then holds the VM for its lifetime, and the parent is released the moment the guest is
//! ready. That makes the parent the only place the steps *around* a boot can happen —
//! publishing ports, stamping what was booted — so `boot` runs in the child and
//! [`after_boot`] in the parent (see `main`, and [`crate::detach`]).
//!
//! What the environment is booted from is recorded in the state dir as its identity: a
//! digest over the resolved plan, with values that came from the host environment reduced to
//! a fingerprint so no secret is written down. A later `up` that resolves to a different
//! digest is drift, and the config's freshness policy says what to do about it — the running
//! VM is not what the config now says it should be, and it is never quietly relabelled as if
//! it were.

mod boot;
pub mod cli;
pub mod config;
pub mod devcontainer;
pub mod endpoints;
mod hooks;
mod identity;
pub mod init;
pub mod list;
pub mod plan;
pub mod schema;
mod session;
mod status;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::dev::config::Freshness;

pub use boot::{boot, build};
pub use identity::plan_diff;
pub use session::{
    LOGIN_SHELL, after_boot, exec_in_guest, exec_in_service, exec_session, guest_cwd, service, stop,
};
pub use status::{doctor, status};

/// What the running environment was booted from: `<state-dir>/dev.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    /// digest of `manifest`, which is what `up` compares
    pub digest: String,
    pub booted_secs: u64,
    /// the `vk` that booted it, as its `--version` reports — an environment built by a
    /// development build is worth telling apart from one built by a release. Defaulted, so
    /// a `dev.json` an older `vk` wrote still loads.
    #[serde(default)]
    pub created_by: String,
    /// the environment as materialized when it booted (see
    /// [`generation_of`](identity::generation_of)) — what the `create` hook's stamp is keyed
    /// on. Defaulted, so a `dev.json` an older `vk` wrote still loads.
    #[serde(default)]
    pub generation: String,
    /// the plan as booted, with host-environment values fingerprinted rather than stored
    pub manifest: serde_json::Value,
}

/// How long to wait for the note the child leaves for its parent.
const TRANSITION_WAIT: Duration = Duration::from_secs(2);
/// How often to look again while joining a boot someone else started.
const INFLIGHT_POLL: Duration = Duration::from_millis(500);

/// The token a managed directory carries for as long as it exists: `<dir>/.vk-generation`.
pub(crate) const GENERATION_MARKER: &str = ".vk-generation";

/// Did this invocation boot the environment, or find it already up? `postStartCommand` runs
/// on the transition, not on an idempotent `up`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Transition {
    Booted,
    Reused,
}

/// What a `vk dev` command says on top of the config. Precedence is the command line, then
/// the config, then whatever `vk run` does with nothing said — the same default as a boot,
/// since a prebuild aimed at a different cache would warm nothing the boot then reads.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub cache_registry: Option<String>,
    pub cache_insecure: bool,
    /// what to do about a running environment that no longer matches, over the config's
    pub freshness: Option<Freshness>,
}

/// The fixtures every submodule's tests build on: a scratch directory that removes itself,
/// the plan they run against, and a one-line hook.
#[cfg(test)]
pub(super) mod testutil {
    use std::path::{Path, PathBuf};

    use crate::dev::config::Freshness;
    use crate::dev::plan::{HookCommand, HookPlan, MountPlan, Plan, Source};

    pub(super) struct TmpDir(pub(super) PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// A directory of this test's own: the tag is not unique across modules (two of them
    /// use `"cache"`), and tests in one binary share a pid, so a counter keeps two of them
    /// from working in — and dropping — the same directory.
    pub(super) fn scratch(tag: &str) -> TmpDir {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vk-dev-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }

    pub(super) fn plan_in(dir: &Path) -> Plan {
        Plan {
            workspace: dir.join("repo"),
            config: dir.join("repo/.virtkit/config.toml"),
            environment: "dev".into(),
            state_dir: dir.join("state"),
            source: Source::Compose {
                file: dir.join("repo/compose.yaml"),
                service: "devcontainer".into(),
                profiles: vec![],
            },
            workspace_folder: Some("/workdir".into()),
            user: Some("dev".into()),
            freshness: Freshness::Ask,
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
            vscode: None,
            managed_dirs: vec![],
            unresolved: vec![],
            secrets: Default::default(),
        }
    }

    /// A plain read-write bind, as a `[dev.mounts.<name>]` resolves to.
    pub(super) fn mount(name: &str, source: impl Into<PathBuf>, to: &str) -> MountPlan {
        MountPlan {
            name: name.into(),
            source: source.into(),
            to: to.into(),
            read_only: false,
            optional: false,
        }
    }

    pub(super) fn shell(line: &str) -> HookPlan {
        HookPlan::Command(HookCommand {
            run: crate::dev::config::Command::Shell(line.into()),
            cwd: None,
            timeout_secs: None,
            required: true,
        })
    }
}
