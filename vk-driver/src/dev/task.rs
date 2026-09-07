//! `vk dev task <name>`: a project command, run where its policy says.
//!
//! The command itself is the project's; this module only decides *where* it runs: attached
//! to the environment already up, in one booted
//! for it, or in a throwaway VM that exists for the length of the command. The config
//! declares that as a policy per task; this carries it out and reproduces the command's exit
//! status, so a hook that calls `vk dev task` behaves exactly as the hook it replaced.
//!
//! An ephemeral run is deliberately not a small `vk dev up`: it boots no LAN, publishes no
//! endpoint, opens no session channel and leaves nothing behind. With `cached-only` the
//! image is restored from the build cache or the run refuses, and a `fallback` target — and
//! only a cache miss, never a failure to reach or run the guest — is what gets built
//! instead.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use vk_core::exec::client::Stdin;

use crate::dev::config::{CheckoutMode, Loaded, Policy};
use crate::dev::plan::{Plan, TaskPlan};

/// The task `name` declares, or an error naming the ones the config does.
pub fn find<'a>(plan: &'a Plan, name: &str) -> Result<&'a TaskPlan> {
    plan.tasks.iter().find(|t| t.name == name).with_context(|| {
        let known: Vec<&str> = plan.tasks.iter().map(|t| t.name.as_str()).collect();
        match known.is_empty() {
            true => format!("no task {name:?} in {}", plan.config.display()),
            false => format!(
                "no task {name:?} in {} (there is {})",
                plan.config.display(),
                known.join(", ")
            ),
        }
    })
}

/// Decide placement once so `boots` and `run` agree on where the task runs.
pub enum Placement {
    /// bring this environment up first, then run the task in it (`require`)
    Boot(Box<Plan>),
    /// run the task in this environment, which is already up
    Attach(Box<Plan>),
    /// nothing is running and the policy is `reuse`: the named environment is missing
    NotRunning(String),
    /// run the task in a throwaway VM
    Ephemeral,
}

impl Placement {
    /// The environment to bring up before the task runs, if any. `main` forks on this (see
    /// [`crate::detach`]), so it is answered before the task itself is.
    pub fn boots(&self) -> Option<&Plan> {
        match self {
            Placement::Boot(plan) => Some(plan),
            _ => None,
        }
    }
}

/// Read the task's policy and say where it will run. Only `require` boots the environment;
/// the others attach to what is running or boot a throwaway VM of their own, which is not
/// the environment and must not be left behind.
pub fn placement(loaded: &Loaded, plan: &Plan, name: &str) -> Result<Placement> {
    let task = find(plan, name)?;
    // `checkout = "overlay"` isolates the workspace only on the ephemeral path (see
    // `dev::task_args`); a policy that can attach would write through to the real workspace
    // whenever the environment is up. Reject the pairing rather than let one task isolate or
    // not by whether something happens to be running.
    if task.checkout == CheckoutMode::Overlay && task.policy != Policy::Ephemeral {
        bail!(
            "task {name}: `checkout = \"overlay\"` needs `policy = \"ephemeral\"` — the other \
             policies attach to a running environment, where overlay does not apply and the \
             task would write the real workspace"
        );
    }
    // Only the policies that use it: resolving is a whole second plan, and an unrelated
    // `reuse` environment that does not resolve is no reason to refuse a `require` task.
    let running = |env: &str| -> Result<Option<Plan>> {
        let plan = crate::dev::plan::resolve(loaded, env)?;
        Ok(crate::dev::running_vm(&plan).is_some().then_some(plan))
    };
    Ok(match task.policy {
        Policy::Require => Placement::Boot(Box::new(crate::dev::plan::resolve(
            loaded,
            &task.environment,
        )?)),
        Policy::Reuse => match running(&task.reuse)? {
            Some(plan) => Placement::Attach(Box::new(plan)),
            None => Placement::NotRunning(task.reuse.clone()),
        },
        Policy::ReuseOrEphemeral => match running(&task.reuse)? {
            Some(plan) => Placement::Attach(Box::new(plan)),
            None => Placement::Ephemeral,
        },
        Policy::Ephemeral => Placement::Ephemeral,
    })
}

/// Run the task at its [`placement`] and return its exit status.
pub async fn run(
    placement: Placement,
    loaded: &Loaded,
    plan: &Plan,
    name: &str,
    extra: &[String],
    cfg: &crate::config::Config,
    over: &crate::dev::Overrides,
) -> Result<ExitCode> {
    let task = find(plan, name)?;
    match placement {
        // A `require` task's environment is up: `main` brought it up before this ran.
        Placement::Boot(target) | Placement::Attach(target) => attach(&target, task, extra).await,
        Placement::NotRunning(environment) => bail!(
            "no running {environment} environment, and task {name} is `policy = \"reuse\"` — \
             `vk dev up` starts one"
        ),
        Placement::Ephemeral => ephemeral(loaded, plan, task, extra, cfg, over).await,
    }
}

/// The task in the running environment, as a session: its user, its `exec-env` plus the
/// task's own, in the workspace folder.
async fn attach(plan: &Plan, task: &TaskPlan, extra: &[String]) -> Result<ExitCode> {
    eprintln!(
        "task {}: running in the {} environment",
        task.name, plan.environment
    );
    let mut argv = task.argv.clone();
    argv.extend_from_slice(extra);
    let env: Vec<(String, String)> = task
        .env
        .iter()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect();
    let result =
        crate::dev::exec_in_guest_with(plan, &argv, None, false, Stdin::Forward, &env).await?;
    Ok(crate::exec::exit(result))
}

/// Run the task in its own VM and tear it down when the command ends. For a `cached-only`
/// environment, build the fallback target only on a cache miss, identified by the run's
/// typed error rather than its message or exit code.
async fn ephemeral(
    loaded: &Loaded,
    plan: &Plan,
    task: &TaskPlan,
    extra: &[String],
    cfg: &crate::config::Config,
    over: &crate::dev::Overrides,
) -> Result<ExitCode> {
    let mut env_plan = crate::dev::plan::resolve(loaded, &task.environment)?;
    // `[environments.<name>]` inherits nothing from `[dev]`, which is right for what an
    // environment *is* — but where built stages are cached is a property of the project and
    // the machine, not of one environment, and a task warmed from another store rebuilds
    // everything. So the dev environment's cache stands in when the task's names none.
    if env_plan.cache.registry.is_none() {
        env_plan.cache = plan.cache.clone();
    }
    env_plan.require_resolved()?;
    eprintln!(
        "task {}: ephemeral {} VM ({})",
        task.name,
        task.environment,
        match env_plan.cached_only {
            true => "cached image only",
            false => "building what the cache misses",
        }
    );
    let args = crate::dev::task_args(&env_plan, over, cfg, task, extra, None, None)?;
    // The scratch directory is this run's alone. The guard removes it however run_ephemeral
    // returns — the command failing, the run refusing, an error on the way out; `exec::exit`
    // below would end the process before any destructor runs, so the guard is dropped first
    // and the process exit is the last thing to happen. A signal that kills `vk` itself
    // leaves the directory behind, with `vk dev gc` the backstop.
    let _scratch = args.state_dir.clone().map(Scratch);
    let outcome = run_ephemeral(&env_plan, task, extra, cfg, over, args).await;
    drop(_scratch);
    Ok(match outcome? {
        Outcome::Done => ExitCode::SUCCESS,
        Outcome::Exit(result) => crate::exec::exit(result),
    })
}

/// Return the outcome so [`ephemeral`] drops the scratch guard before `exec::exit`
/// ends the process.
enum Outcome {
    /// the run finished with no guest status to reproduce
    Done,
    /// reproduce the guest command's own exit — code or terminating signal
    Exit(vk_core::messages::CmdResult),
}

/// A throwaway run's state directory, removed when this goes out of scope: its sockets,
/// logs and root image are that run's alone (the built stages stay in the shared cache).
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn run_ephemeral(
    env_plan: &Plan,
    task: &TaskPlan,
    extra: &[String],
    cfg: &crate::config::Config,
    over: &crate::dev::Overrides,
    args: crate::run::RunArgs,
) -> Result<Outcome> {
    match crate::run::run(&args, cfg).await {
        Ok(()) => Ok(Outcome::Done),
        Err(e) => match (crate::run::guest_exit(&e), &env_plan.fallback_target) {
            (Some(result), _) => Ok(Outcome::Exit(result)),
            (None, Some(target)) if crate::build::not_cached(&e) => {
                eprintln!(
                    "task {}: cache miss, building the fallback target {target}",
                    task.name
                );
                // Reuse this run's directory while building the stage missing from the cache.
                let fallback = crate::dev::task_args(
                    env_plan,
                    over,
                    cfg,
                    task,
                    extra,
                    Some(target),
                    args.state_dir.as_deref(),
                )?;
                match crate::run::run(&fallback, cfg).await {
                    Ok(()) => Ok(Outcome::Done),
                    Err(e) => match crate::run::guest_exit(&e) {
                        Some(result) => Ok(Outcome::Exit(result)),
                        None => Err(e),
                    },
                }
            }
            (None, _) => Err(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    #[test]
    fn scratch_guard_removes_the_dir_on_drop() {
        let dir = std::env::temp_dir().join(format!("vk-task-scratch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("root.ext4"), b"x").unwrap();
        assert!(dir.is_dir());
        drop(Some(Scratch(dir.clone())));
        assert!(
            !dir.exists(),
            "the guard removes the whole state dir, contents and all"
        );
    }

    /// A workspace with a `[dev.tasks.<name>]` per policy. Nothing is registered against its
    /// derived state directory, so the reusing policies see their not-running branch.
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("vk-task-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".virtkit")).unwrap();
        std::fs::write(
            root.join(".virtkit/config.toml"),
            r#"
schema = 1

[dev]
image = "alpine"
workspace = "/w"

[dev.tasks.eph]
run = "true"
policy = "ephemeral"

[dev.tasks.req]
run = "true"
policy = "require"

[dev.tasks.reu]
run = "true"
policy = "reuse"

[dev.tasks.roe]
run = "true"
policy = "reuse-or-ephemeral"

[dev.tasks.eph-overlay]
run = "true"
policy = "ephemeral"
checkout = "overlay"

[dev.tasks.reuse-overlay]
run = "true"
policy = "reuse-or-ephemeral"
checkout = "overlay"
"#,
        )
        .unwrap();
        Fixture(root)
    }

    fn placement_of(root: &Path, name: &str) -> Result<Placement> {
        let loaded =
            crate::dev::config::load(crate::dev::config::discover(root, Some(root), None).unwrap())
                .unwrap();
        let plan = crate::dev::plan::resolve(&loaded, "dev").unwrap();
        placement(&loaded, &plan, name)
    }

    #[test]
    fn placement_maps_each_policy_with_no_environment_running() {
        let f = fixture("placement");
        // Nothing runs against the derived state dir, so the reusing policies take their
        // not-running branch. `Attach` needs a live VM and is not exercised here.
        assert!(matches!(
            placement_of(&f.0, "eph").unwrap(),
            Placement::Ephemeral
        ));
        assert!(matches!(
            placement_of(&f.0, "req").unwrap(),
            Placement::Boot(_)
        ));
        assert!(matches!(
            placement_of(&f.0, "reu").unwrap(),
            Placement::NotRunning(_)
        ));
        assert!(matches!(
            placement_of(&f.0, "roe").unwrap(),
            Placement::Ephemeral
        ));
    }

    #[test]
    fn overlay_is_allowed_on_ephemeral_and_rejected_when_a_policy_can_attach() {
        let f = fixture("overlay");
        assert!(matches!(
            placement_of(&f.0, "eph-overlay").unwrap(),
            Placement::Ephemeral
        ));
        let e = placement_of(&f.0, "reuse-overlay")
            .err()
            .expect("overlay on a reusing policy must be rejected");
        assert!(e.to_string().contains("overlay"), "{e}");
        assert!(e.to_string().contains("ephemeral"), "{e}");
    }
}
