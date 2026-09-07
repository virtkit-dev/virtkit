//! `vk dev task <name>`: a project command, run where its policy says.
//!
//! A project's checks are the project's — a pre-commit hook stays the script it was. What
//! belongs here is *where* it runs: attached to the environment already up, in one booted
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

use crate::dev::config::{Loaded, Policy};
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

/// Where a task runs, decided once — `boots` and `run` used to match on the policy
/// separately, and a task whose two answers disagreed attached to nothing.
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

/// Run the task where [`placement`] said, and answer with what its command exited.
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

/// The task in a VM of its own, torn down with the command. A `cached-only` environment
/// whose stage is not in the cache falls back to the configured target — that miss alone,
/// which is why the run's own typed refusal is what this branches on rather than a message
/// or an exit code.
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
    // From here on the directory is removed however this returns — the command failing, the
    // run refusing, an error on the way out. A signal still leaves it behind, since nothing
    // runs then: `vk dev gc` is the backstop for that.
    let _scratch = args.state_dir.clone().map(Scratch);
    run_ephemeral(&env_plan, task, extra, cfg, over, args).await
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
) -> Result<ExitCode> {
    match crate::run::run(&args, cfg).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) => match (crate::run::guest_exit(&e), &env_plan.fallback_target) {
            (Some(result), _) => Ok(crate::exec::exit(result)),
            (None, Some(target)) if crate::build::not_cached(&e) => {
                eprintln!(
                    "task {}: cache miss, building the fallback target {target}",
                    task.name
                );
                // The same directory: this is the same run, with the stage the cache
                // could not hand it built instead.
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
                    Ok(()) => Ok(ExitCode::SUCCESS),
                    Err(e) => match crate::run::guest_exit(&e) {
                        Some(result) => Ok(crate::exec::exit(result)),
                        None => Err(e),
                    },
                }
            }
            (None, _) => Err(e),
        },
    }
}
