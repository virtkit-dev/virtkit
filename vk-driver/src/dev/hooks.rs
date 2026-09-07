//! The lifecycle commands a config declares, and what has to hold before any of them run.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use vk_core::exec::client::Stdin;

use crate::dev::plan::{HookCommand, HookPlan, Plan};

use super::session::exec_in_guest_with;

/// Where a hook runs.
#[derive(Clone, Copy)]
pub(crate) enum Where {
    /// on this machine, from the workspace — before the environment exists
    Host,
    /// in the guest, as the configured user in the workspace folder, with `exec-env`
    Guest,
}

/// `<state-dir>/lifecycle/<hook>` — written only once its command has succeeded, and holding
/// the generation ([`generation_of`](super::identity::generation_of)) it succeeded for, so
/// `hooks.create` runs again for an environment whose image or writable storage was
/// materialized afresh, and not for one merely restarted. A file an older `vk` wrote holds a
/// config digest instead, which matches no generation, so the first boot after an upgrade
/// runs the hook once more.
fn stamp_path(plan: &Plan, hook: &str) -> PathBuf {
    plan.state_dir.join("lifecycle").join(hook)
}

pub(super) fn stamped(plan: &Plan, hook: &str, generation: &str) -> bool {
    std::fs::read_to_string(stamp_path(plan, hook)).is_ok_and(|s| s.trim() == generation)
}

fn stamp(plan: &Plan, hook: &str, digest: &str) -> Result<()> {
    let path = stamp_path(plan, hook);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // `with_file_name`, not `with_extension`: a hook whose name carries a dot would have
    // that suffix replaced rather than a new one added.
    let tmp = path.with_file_name(format!("{hook}.tmp"));
    std::fs::write(&tmp, digest).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("publishing {}", path.display()))
}

/// Run one hook. A [`HookPlan::Group`] runs its members one after another, in name order, and
/// never concurrently — they share one guest and routinely build on each other. The group is
/// the unit: every member is attempted, and a required one failing fails the group. A
/// best-effort command's failure is reported and does not stop the operation. `env` is added
/// to `exec-env` for a guest hook, and to the host environment for a host one.
pub(crate) async fn run_hook(
    plan: &Plan,
    name: &str,
    hook: &HookPlan,
    place: Where,
    env: &[(String, String)],
) -> Result<()> {
    let cmd = match hook {
        HookPlan::Group(group) => {
            let mut failures = Vec::new();
            for (member, hook) in group {
                let label = format!("{name}.{member}");
                if let Err(e) = Box::pin(run_hook(plan, &label, hook, place, env)).await {
                    failures.push(format!("{label}: {e:#}"));
                }
            }
            if !failures.is_empty() {
                bail!("{name}: {}", failures.join("; "));
            }
            return Ok(());
        }
        HookPlan::Command(cmd) => cmd,
    };
    eprintln!("virtkit: {name}: {}", hook.describe());
    let timeout = cmd.timeout_secs.map(Duration::from_secs);
    let run = async {
        match place {
            Where::Host => run_on_host(plan, name, cmd, env).await,
            Where::Guest => run_in_guest(plan, name, cmd, env).await,
        }
    };
    let result = match timeout {
        Some(limit) => match tokio::time::timeout(limit, run).await {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!(
                "{name} did not finish within {}s",
                limit.as_secs()
            )),
        },
        None => run.await,
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if !cmd.required => {
            eprintln!("virtkit: {e:#} — best effort, continuing");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// A host-side hook, from the workspace (or its `cwd` under it): it exists to prepare what
/// the boot then reads.
async fn run_on_host(
    plan: &Plan,
    name: &str,
    cmd: &HookCommand,
    env: &[(String, String)],
) -> Result<()> {
    let dir = match &cmd.cwd {
        Some(d) => plan.workspace.join(d),
        None => plan.workspace.clone(),
    };
    let argv = cmd.argv();
    let (program, rest) = argv.split_first().context("empty argv")?;
    let mut child = tokio::process::Command::new(program)
        .args(rest)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(&dir)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("{name}: running {program:?}"))?;
    let status = child
        .wait()
        .await
        .with_context(|| format!("{name}: waiting for {program:?}"))?;
    if !status.success() {
        bail!("{name} failed ({status})");
    }
    Ok(())
}

/// A guest-side hook, run the way the dev tooling runs anything in the environment.
async fn run_in_guest(
    plan: &Plan,
    name: &str,
    cmd: &HookCommand,
    env: &[(String, String)],
) -> Result<()> {
    // A relative `cwd` is under the workspace folder, as a host one is under the workspace.
    let dir = match (&cmd.cwd, &plan.workspace_folder) {
        (Some(d), _) if d.starts_with('/') => Some(d.clone()),
        (Some(d), Some(folder)) => Some(format!("{folder}/{d}")),
        (Some(d), None) => Some(d.clone()),
        (None, folder) => folder.clone(),
    };
    // A hook has nothing to read, and `vk dev up` runs more than one of them in this
    // process — which is exactly where forwarding stdin would be unsound.
    let result = exec_in_guest_with(plan, &cmd.argv(), dir, false, Stdin::Closed, env).await?;
    match result.code {
        Some(0) | None => Ok(()),
        Some(code) => bail!("{name} exited {code}"),
    }
}

/// The hooks that run once the environment is up after a boot: `create` for a generation
/// that has not had it, then `start`. A failure stops the ones after it, and leaves no stamp
/// saying it succeeded. A `None` generation — nothing filed for the booted VM to read it off
/// — runs `create` and stamps nothing, so the next boot runs it rather than skipping it on a
/// record of what it was initialized for.
///
/// `start` is deliberately not stamped: it runs on every fresh boot, and only on a fresh
/// boot — an `up` that reuses a running environment never gets here. Its failure is the
/// operation's, and because [`after_boot`](super::session::after_boot) writes the identity
/// only once this returns, an environment whose start hook failed records nothing and is
/// driven through the whole sequence again by the next `up` rather than reported as a match.
pub(super) async fn run_start_hooks(plan: &Plan, generation: Option<&str>) -> Result<()> {
    if let Some(hook) = &plan.hooks.create
        && !generation.is_some_and(|g| stamped(plan, "create", g))
    {
        run_hook(plan, "hooks.create", hook, Where::Guest, &[]).await?;
        if let Some(generation) = generation {
            stamp(plan, "create", generation)?;
        }
    }
    if let Some(hook) = &plan.hooks.start {
        run_hook(plan, "hooks.start", hook, Where::Guest, &[]).await?;
    }
    Ok(())
}

/// What the config requires of this `vk`, checked before anything is built or started so a
/// too-old binary fails with the executable and version it is, not halfway into a boot.
pub(super) fn check_requirements(plan: &Plan, cfg: &crate::config::Config) -> Result<()> {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vk"));
    if let Some(min) = &plan.requires.min_version {
        let min: crate::check::Version = min
            .parse()
            .map_err(|e| anyhow::anyhow!("requires.min-version {min:?}: {e}"))?;
        let own = crate::check::Version::own().map_err(|e| anyhow::anyhow!(e))?;
        if own < min {
            bail!(
                "{} is vk {own}, and {} requires at least {min} — `vk update`, or point \
                 VIRTKIT_VK at a newer build",
                exe.display(),
                plan.config.display()
            );
        }
    }
    let mut missing = Vec::new();
    for name in &plan.requires.features {
        let Some(feature) = crate::check::Feature::from_name(name) else {
            bail!("requires.features names {name:?}, which is not a feature `vk check` knows");
        };
        if let Err(why) = crate::check::probe(cfg, feature) {
            missing.push(format!("{name}: {why}"));
        }
    }
    if !missing.is_empty() {
        bail!(
            "{} does not provide what {} requires:\n  {}",
            exe.display(),
            plan.config.display(),
            missing.join("\n  ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::boot::ensure_state_dir;
    use crate::dev::identity::{generation_of, identity_of};
    use crate::dev::testutil::{plan_in, scratch, shell};

    #[tokio::test]
    async fn a_host_hook_runs_from_the_workspace_and_its_failure_stops_the_boot() {
        let t = scratch("hostmark");
        let plan = plan_in(&t.0);
        std::fs::create_dir_all(&plan.workspace).unwrap();
        ensure_state_dir(&plan).unwrap();

        // cwd is the workspace: what the hook prepares is what the boot then reads.
        run_hook(
            &plan,
            "hooks.init",
            &shell("pwd > where; echo prepared > marker"),
            Where::Host,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(plan.workspace.join("where"))
                .unwrap()
                .trim(),
            plan.workspace.to_string_lossy()
        );
        assert!(plan.workspace.join("marker").is_file());

        let failed = run_hook(&plan, "hooks.init", &shell("exit 3"), Where::Host, &[]).await;
        assert!(failed.is_err(), "a failing hook must not be swallowed");

        // A named group runs every member and fails as a whole if any member does.
        let mut group = std::collections::BTreeMap::new();
        group.insert("one".to_string(), shell("touch one"));
        group.insert("two".to_string(), shell("touch two; exit 1"));
        let err = run_hook(
            &plan,
            "hooks.create",
            &HookPlan::Group(group),
            Where::Host,
            &[],
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("two"), "{err:#}");
        assert!(
            plan.workspace.join("one").is_file(),
            "the whole group still ran"
        );

        // The options: a working directory under the workspace, a failure that is reported
        // and not fatal, and a time limit that is.
        std::fs::create_dir_all(plan.workspace.join("sub")).unwrap();
        let detailed = |line: &str, cwd: Option<&str>, timeout: Option<u64>, required: bool| {
            HookPlan::Command(HookCommand {
                run: crate::dev::config::Command::Shell(line.into()),
                cwd: cwd.map(str::to_string),
                timeout_secs: timeout,
                required,
            })
        };
        run_hook(
            &plan,
            "hooks.init",
            &detailed("pwd > where", Some("sub"), None, true),
            Where::Host,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(plan.workspace.join("sub/where"))
                .unwrap()
                .trim(),
            plan.workspace.join("sub").to_string_lossy()
        );
        run_hook(
            &plan,
            "hooks.init",
            &detailed("exit 5", None, None, false),
            Where::Host,
            &[],
        )
        .await
        .expect("best effort: reported, not fatal");
        let err = run_hook(
            &plan,
            "hooks.init",
            &detailed("sleep 5", None, Some(1), true),
            Where::Host,
            &[],
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("within 1s"), "{err:#}");
    }

    #[test]
    fn the_create_stamp_is_per_generation_and_only_written_on_success() {
        let t = scratch("stamp");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();
        assert!(!stamped(&plan, "create", "abc"), "nothing has run yet");
        stamp(&plan, "create", "abc").unwrap();
        assert!(
            stamped(&plan, "create", "abc"),
            "a restart must not re-run it"
        );
        // Materialized afresh — a rebuilt image, a reset directory: the hook that sets one
        // up runs again.
        assert!(!stamped(&plan, "create", "def"));
        // A stamp an older vk wrote holds a config digest, which is no generation, so the
        // first boot after an upgrade runs the hook once more.
        let mut plan = plan;
        plan.managed_dirs = vec![plan.state_dir.join("store")];
        ensure_state_dir(&plan).unwrap();
        let (digest, _) = identity_of(&plan, None).unwrap();
        stamp(&plan, "create", &digest).unwrap();
        assert!(!stamped(
            &plan,
            "create",
            &generation_of(&plan, "ext4:aaaa")
        ));
    }

    #[tokio::test]
    async fn a_hook_receives_the_environment_an_operation_hands_it() {
        let t = scratch("hookenv");
        let plan = plan_in(&t.0);
        std::fs::create_dir_all(&plan.workspace).unwrap();
        run_hook(
            &plan,
            "editor.vscode.reconcile",
            &shell("printf %s \"$VK_VSCODE_CLI\" > cli"),
            Where::Host,
            &[("VK_VSCODE_CLI".into(), "/srv/bin/code-server".into())],
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(plan.workspace.join("cli")).unwrap(),
            "/srv/bin/code-server"
        );
    }
}
