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
pub mod editor;
pub mod endpoints;
mod hooks;
mod identity;
pub mod init;
pub mod list;
pub mod plan;
pub(crate) mod prune;
pub mod schema;
mod session;
pub mod sshsetup;
mod status;
pub mod storage;
mod table;
pub mod targets;
pub mod task;
pub mod wsl;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::dev::config::Freshness;

pub(crate) use boot::{alias_for, lock_holder};
pub use boot::{boot, build, task_args};
pub(crate) use hooks::{Where, run_hook};
pub use identity::plan_diff;
pub(crate) use identity::write_compose_snapshot;
pub use session::{
    LOGIN_SHELL, after_boot, ask_on_terminal, exec_in_guest, exec_in_guest_with, exec_in_service,
    exec_session, guest_cwd, launch_checks, launch_editor, on_terminal, running_vm, service,
    service_within, stop,
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
    /// the durable and managed storage backings this environment declared at boot, absolute:
    /// what `vk dev prune --storage` removes. Recorded so prune can find them by name, without
    /// re-reading the workspace's config — which may have moved or changed. `None` from a
    /// `dev.json` written before this was recorded; prune by name then falls back to its
    /// fixed-name storage and says the declared backings could not be identified.
    #[serde(default)]
    pub storage_backings: Option<Vec<std::path::PathBuf>>,
    /// whether the VM's own boot readied it. False when a later claim completes setup left
    /// unfinished, or when an older `vk` omitted the flag from `dev.json`. Only an explicit
    /// `true` counts as the VM's own boot.
    #[serde(default)]
    pub readied_by_its_boot: bool,
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
    /// what to do about a running environment that no longer matches, over the config's `freshness`
    pub freshness: Option<Freshness>,
    /// boot only what is already built: a stage is restored from the cache or the boot fails
    /// (`vk dev start`)
    pub no_build: bool,
}

/// The fixtures every submodule's tests build on: a scratch directory that removes itself,
/// the plan they run against, and a one-line hook.
#[cfg(test)]
pub(crate) mod testutil {
    use std::path::{Path, PathBuf};

    use crate::dev::config::Freshness;
    use crate::dev::plan::{HookCommand, HookPlan, MountPlan, Plan, Source};

    pub(crate) struct TmpDir(pub(crate) PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// A directory of this test's own: the tag is not unique across modules (two of them
    /// use `"cache"`), and tests in one binary share a pid, so a counter keeps two of them
    /// from working in — and dropping — the same directory.
    pub(crate) fn scratch(tag: &str) -> TmpDir {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vk-dev-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }

    /// Coordinates environment changes with child spawns that take this guard. A concurrent
    /// environment read during `set_var` is unsafe. Inherited flocks need no serialization
    /// because [`vk_fs::LockFile`] explicitly unlocks them. Recover poison so a panic in one
    /// test does not fail later tests.
    pub(crate) fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
        ENV.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Isolates VM lookups with an empty name index and registry. Holds [`env_guard`]
    /// until the original environment has been restored.
    pub(crate) struct Homes {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
        // Dropped after `drop` has put the variables back: the directory, then the guard.
        dir: TmpDir,
        _env: std::sync::MutexGuard<'static, ()>,
    }

    impl Homes {
        pub(crate) fn new(tag: &str) -> Homes {
            let env = env_guard();
            let dir = scratch(tag);
            let vars = ["XDG_STATE_HOME", "XDG_DATA_HOME"];
            let saved = vars.map(|v| (v, std::env::var_os(v))).to_vec();
            for v in vars {
                // SAFETY: serialized by env_guard, put back on drop.
                unsafe { std::env::set_var(v, dir.0.join(v)) };
            }
            Homes {
                saved,
                dir,
                _env: env,
            }
        }

        pub(crate) fn dir(&self) -> &Path {
            &self.dir.0
        }

        /// Name `state` `name` in this index.
        pub(crate) fn name(&self, state: &Path, name: &str) {
            crate::names::Index::open()
                .unwrap()
                .claim_exact(state, name)
                .unwrap();
        }
    }

    impl Drop for Homes {
        fn drop(&mut self) {
            for (v, val) in &self.saved {
                // SAFETY: still under env_guard, which is released after this.
                match val {
                    Some(val) => unsafe { std::env::set_var(v, val) },
                    None => unsafe { std::env::remove_var(v) },
                }
            }
        }
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
            nested: crate::dev::config::Nested::Off,
            egress: None,
            mounts: vec![],
            container_env: vec![],
            exec_env: vec![],
            endpoints: vec![],
            host_exec: None,
            ssh: Default::default(),
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

    /// `plan`'s VM as up, managed by this process: its registry entry, and the state dir lock
    /// its `vk run` would hold, which is what makes the registry read it as alive. Only in a
    /// test process of its own, given a scratch `XDG_DATA_HOME`: the registry is per user.
    pub(super) fn register_vm(plan: &Plan) -> (crate::vms::Registration, vk_fs::LockFile) {
        register_vm_as(plan, std::process::id())
    }

    /// Like [`register_vm`], with `pid` as the managing process that stop signals. Since this
    /// process holds the lock, `vk stop DIR` signals `pid`, while [`crate::vms::stop_entry`]
    /// and [`crate::dev::stop`] read the entry as replaced and signal nothing.
    pub(super) fn register_vm_as(
        plan: &Plan,
        pid: u32,
    ) -> (crate::vms::Registration, vk_fs::LockFile) {
        std::fs::create_dir_all(&plan.state_dir).unwrap();
        let lock = crate::dev::list::try_lock_state_dir(&plan.state_dir).expect("lock it");
        (register_entry(plan, pid), lock)
    }

    /// Like [`register_vm`], managed by a stand-in that takes the state dir lock itself, as a
    /// `vk run` does: procfs names it as the holder, and a stop that signals it brings the VM
    /// down unless `ignores_term`.
    pub(super) fn register_vm_in_child(
        plan: &Plan,
        ignores_term: bool,
    ) -> (crate::vms::Registration, StandIn) {
        std::fs::create_dir_all(&plan.state_dir).unwrap();
        let stand_in = StandIn::locking(&plan.state_dir, ignores_term);
        // With its start time, as `vk run` records it.
        let ticks = crate::usage::proc_starttime(i32::try_from(stand_in.id()).unwrap());
        (register_entry_at(plan, stand_in.id(), ticks), stand_in)
    }

    /// Record `plan`'s VM as managed by `pid`, taking no lock: alive only while something
    /// else holds the state dir's.
    pub(super) fn register_entry(plan: &Plan, pid: u32) -> crate::vms::Registration {
        register_entry_at(plan, pid, None)
    }

    /// [`register_entry`], recording `ticks` as the start time of `pid`.
    fn register_entry_at(plan: &Plan, pid: u32, ticks: Option<u64>) -> crate::vms::Registration {
        let entry = serde_json::from_value(serde_json::json!({
            "state_dir": crate::vms::canonical(&plan.state_dir),
            "pid": pid,
            "label": "devcontainer",
            "exec_addr": "unused",
            "created_secs": 7,
            "pid_start_ticks": ticks,
        }))
        .unwrap();
        crate::vms::register(entry)
    }

    /// Stand-in for a registered VM's `vk run`, keeping stop signals out of the test process.
    /// Its process group is killed on drop or test process death.
    pub(crate) struct StandIn(crate::testchild::Kept);

    impl StandIn {
        pub(crate) fn spawn() -> Self {
            Self(crate::testchild::Kept::spawn(
                std::process::Command::new("sleep").arg("600"),
            ))
        }

        /// A stand-in holding `dir`'s lock for as long as it runs; one that `ignores_term`
        /// outlasts any stop.
        pub(crate) fn locking(dir: &Path, ignores_term: bool) -> Self {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::process::CommandExt;
            let dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
            let mut cmd = std::process::Command::new("sleep");
            cmd.arg("600");
            // SAFETY: only `signal`, `open` and `flock` run between fork and exec, all
            // async-signal-safe. The descriptor is left open across the exec, so the lock lasts
            // as long as the `sleep`; an ignored signal stays ignored across it, so the stand-in
            // ignores a stop from the moment it exists.
            unsafe {
                cmd.pre_exec(move || {
                    if ignores_term && libc::signal(libc::SIGTERM, libc::SIG_IGN) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                    let fd = libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
                    if fd < 0 || libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            Self(crate::testchild::Kept::spawn(&mut cmd))
        }

        pub(crate) fn id(&self) -> u32 {
            self.0.id()
        }

        /// How it exited, once it has.
        pub(crate) fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
            self.0.try_wait().unwrap()
        }

        pub(crate) fn alive(&mut self) -> bool {
            self.try_wait().is_none()
        }
    }

    /// Set by [`mark_child`] to `<pid>:<test>`: the process that spawned the child, and
    /// the one test the child was spawned to run.
    const CHILD_OF: &str = "VK_TEST_CHILD_OF";

    /// Mark `cmd` for [`child_marker`]. The caller must pass `--exact` with `name`.
    pub(crate) fn mark_child<'a>(
        cmd: &'a mut std::process::Command,
        name: &str,
    ) -> &'a mut std::process::Command {
        cmd.env(CHILD_OF, format!("{}:{name}", std::process::id()))
    }

    /// Prepare a marked child to run only `name`.
    pub(crate) fn child_test(name: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", name, "--nocapture"]);
        mark_child(&mut cmd, name);
        cmd
    }

    /// Return `None` if `var` is unset. Otherwise require the parent PID and exact test
    /// filter recorded by [`mark_child`] before returning its value. An inherited marker
    /// could lower the shared harness's descriptor limit or trigger real garbage collection.
    pub(crate) fn child_marker(var: &str) -> Option<std::ffi::OsString> {
        let value = std::env::var_os(var)?;
        let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
        // SAFETY: getppid has no preconditions and cannot fail.
        let parent = unsafe { libc::getppid() };
        let of = std::env::var(CHILD_OF).ok();
        assert!(
            marked(args.get(1..).unwrap_or_default(), of.as_deref(), parent),
            "{var} is set, but this is not the child process a test spawned for it \
             ({CHILD_OF}={of:?}, parent pid {parent}, args {args:?}): unset {var}"
        );
        Some(value)
    }

    /// Check the parent PID and test arguments against the `<pid>:<test>` marker.
    fn marked(args: &[std::ffi::OsString], of: Option<&str>, parent: libc::pid_t) -> bool {
        of.and_then(|of| of.split_once(':'))
            .is_some_and(|(pid, name)| pid.parse() == Ok(parent) && runs_only(args, name))
    }

    /// Check the arguments after the executable for `--exact` and a single filter, `name`.
    /// A separate option value counts as another filter.
    pub(crate) fn runs_only(args: &[std::ffi::OsString], name: &str) -> bool {
        let mut filters = args
            .iter()
            .filter(|a| !a.as_encoded_bytes().starts_with(b"-"));
        args.iter().any(|a| a == "--exact")
            && filters.next().is_some_and(|f| f == name)
            && filters.next().is_none()
    }

    /// A harmless child branch, for [`an_inherited_or_shared_marker_is_refused`].
    #[test]
    fn marker_probe() {
        if child_marker("VK_TEST_MARKER_PROBE").is_some() {
            println!("probed");
        }
    }

    #[test]
    fn a_marked_child_runs_its_one_test_only() {
        let args = |a: &[&str]| {
            a.iter()
                .map(Into::into)
                .collect::<Vec<std::ffi::OsString>>()
        };
        let of = Some("7:m::t");
        assert!(marked(&args(&["--exact", "m::t", "--nocapture"]), of, 7));
        assert!(
            !marked(&args(&["--exact", "m::t"]), of, 8),
            "another parent"
        );
        assert!(!marked(&args(&["--exact", "m::t"]), None, 7), "no stamp");
        assert!(!marked(&args(&["m::t"]), of, 7), "a prefix filter");
        assert!(
            !marked(&args(&["--exact", "m::t", "m::u"]), of, 7),
            "a second filter"
        );
        assert!(!marked(&args(&["--exact", "m::u"]), of, 7), "another test");
        assert!(!marked(&args(&["--exact", "m::t", "--skip", "m"]), of, 7));
    }

    #[test]
    fn an_inherited_or_shared_marker_is_refused() {
        const PROBE: &str = "dev::testutil::marker_probe";
        let _guard = env_guard();
        let output = child_test(PROBE)
            .env("VK_TEST_MARKER_PROBE", "1")
            .output()
            .unwrap();
        ran_alone(PROBE, &output);
        assert!(String::from_utf8_lossy(&output.stdout).contains("probed"));
        let refused = |output: std::process::Output| {
            assert!(!output.status.success(), "{output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(!stdout.contains("probed"), "{output:?}");
            // The panic message, on stderr under `--nocapture`.
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("VK_TEST_MARKER_PROBE is set, but"),
                "{output:?}"
            );
        };
        refused(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", PROBE, "--nocapture"])
                .env("VK_TEST_MARKER_PROBE", "1")
                .env_remove(CHILD_OF)
                .output()
                .unwrap(),
        );
        refused(
            child_test(PROBE)
                .arg("dev::testutil::a_marked_child_runs_its_one_test_only")
                .env("VK_TEST_MARKER_PROBE", "1")
                .output()
                .unwrap(),
        );
    }

    /// Rerun test `name` in its own process with `XDG_DATA_HOME` under `dir` and `var` set to
    /// `dir`, which the child reads with [`child_marker`].
    pub(crate) fn in_child(name: &str, var: &str, dir: &Path) {
        let _guard = env_guard();
        let output = child_test(name)
            .env(var, dir)
            .env("XDG_DATA_HOME", dir.join("data"))
            .output()
            .unwrap();
        ran_alone(name, &output);
    }

    /// Require a successful run of one test. A filter matching no tests also exits 0.
    pub(crate) fn ran_alone(name: &str, output: &std::process::Output) {
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("1 passed"),
            "{name} did not run: {output:?}"
        );
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
