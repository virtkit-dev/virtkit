//! Working in a running environment: what an attach settles, and what a session runs.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use vk_core::exec::client::Stdin;

use crate::dev::plan::Plan;

use super::boot::take_transition;
use super::hooks::run_start_hooks;
use super::identity::{
    booted_wrapper_digest, generation_of, identity_of, own_version, root_identity, write_identity,
};
use super::{Identity, Transition};

/// Whether there is a terminal to ask a question on — stdin to read the answer from and
/// stderr to print it to.
pub fn on_terminal() -> bool {
    // SAFETY: isatty has no failure mode beyond returning 0.
    unsafe { libc::isatty(0) == 1 && libc::isatty(2) == 1 }
}

/// A yes/no question, answered on the terminal — and answered "no" where there is none, so
/// a script never hangs on a prompt it cannot see.
pub fn ask_on_terminal(question: &str) -> Result<bool> {
    if !on_terminal() {
        return Ok(false);
    }
    eprint!("virtkit: {question} [y/N] ");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading the answer")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// This plan's VM, if it is up.
pub fn running_vm(plan: &Plan) -> Option<crate::vms::VmEntry> {
    crate::vms::running()
        .into_iter()
        .find(|e| e.state_dir == plan.state_dir)
}

/// Everything that happens once the guest is up: record what was booted, and publish the
/// config's endpoints. Runs in the parent (see the module docs).
///
/// The identity file is written *last*, once every readiness step has succeeded — the
/// session environment, the endpoints, `hooks.create` and `hooks.start`. It is what a joining
/// `vk dev up` waits for and what the next one compares against, so an environment whose
/// start hook failed must not carry one: it is up, but it is not ready, and the next `up`
/// drives the whole sequence again rather than reporting a match.
pub async fn after_boot(plan: &Plan) -> Result<()> {
    let transition = take_transition(plan, std::process::id())
        .await
        .unwrap_or(Transition::Reused);
    // Whichever this is, the session environment is the config's rather than the boot's:
    // it is what the *next* session should see.
    sync_session_env(plan).await;
    if transition == Transition::Reused {
        // Attaching to what is running, which may not be what the config now says: the
        // recorded identity stays the running environment's own, and the hooks that belong
        // to a start do not run. Reusing is not relabelling.
        return Ok(());
    }
    let (digest, manifest) = identity_of(plan, booted_wrapper_digest(plan).as_deref())?;
    // What was actually booted, read off the registry entry the boot filed. `None` where
    // there is no entry to read it from, which leaves the creation hook unstamped rather
    // than stamped with something that describes nothing.
    let generation = running_vm(plan).map(|vm| generation_of(plan, &root_identity(plan, &vm)));
    run_start_hooks(plan, generation.as_deref()).await?;
    write_identity(
        plan,
        &Identity {
            digest,
            booted_secs: crate::vms::unix_now(),
            created_by: own_version(),
            generation: generation.unwrap_or_default(),
            manifest,
        },
    )
}

/// The `exec-env` file the guest's SSH server reads, and the names left out of it.
///
/// The format is one `NAME=value` per line, so a name or a value carrying a newline cannot
/// be expressed and is skipped — the caller says which, because a variable that silently
/// stops existing in half the sessions is worse than one that never worked.
fn session_env_text(env: &[crate::dev::plan::EnvVar]) -> (String, Vec<String>) {
    let mut text = String::new();
    let mut skipped = Vec::new();
    for e in env {
        if e.name.contains('\n') || e.value.contains('\n') {
            skipped.push(e.name.replace('\n', "\\n"));
            continue;
        }
        text.push_str(&format!("{}={}\n", e.name, e.value));
    }
    (text, skipped)
}

/// Put the plan's `exec-env` where the guest's SSH server reads every session's environment
/// from ([`vk_core::runcfg::SESSION_ENV_PATH`]), so Remote-SSH's server and its terminals
/// see what `vk dev exec` and `vk dev shell` do. Written as root through the exec channel,
/// the text travelling in the command's own environment rather than on its argv, and
/// replaced atomically; an empty `exec-env` clears what an earlier config left. Best
/// effort: an environment whose image has no `sh` still comes up, with a note.
///
/// The text rides in one `VK_SESSION_ENV=` string through an `execve`, so the whole
/// `exec-env` is bounded by the kernel's `MAX_ARG_STRLEN` (128 KiB); past that the exec
/// fails with a bare `E2BIG`, reported here as the delivery failing.
async fn sync_session_env(plan: &Plan) {
    if plan.require_resolved().is_err() {
        return;
    }
    let path = vk_core::runcfg::SESSION_ENV_PATH;
    let (text, skipped) = session_env_text(&plan.exec_env);
    if !skipped.is_empty() {
        eprintln!(
            "virtkit: exec-env {} not delivered to SSH sessions: a name or value containing a \
             newline cannot be written to {path}",
            skipped.join(", ")
        );
    }
    let script =
        "umask 077 && printf %s \"$VK_SESSION_ENV\" >\"$1.tmp\" && mv -f \"$1.tmp\" \"$1\"";
    let run = async {
        let entry = crate::vms::resolve_one(Some(&plan.state_dir))?;
        let addr: vk_core::addr::SocketAddr = entry.exec_addr.parse()?;
        let result = crate::exec::run(
            addr,
            false,
            false,
            vec![format!("VK_SESSION_ENV={text}")],
            None,
            false,
            Some("root".into()),
            "sh".into(),
            vec!["-c".into(), script.into(), "sh".into(), path.into()],
            Stdin::Closed,
        )
        .await?;
        if result.code != Some(0) {
            bail!("sh exited with {:?}", result.code.or(result.signal));
        }
        anyhow::Ok(())
    };
    if let Err(e) = run.await {
        eprintln!("virtkit: exec-env not delivered to SSH sessions ({path}): {e:#}");
    }
}

/// The one way anything runs in the primary: as `user` (else the config's), in `dir` (else
/// the workspace folder), with the plan's `exec-env` plus `extra` — the scope for what the
/// dev tooling runs, as against the guest's own processes.
async fn exec_with(
    plan: &Plan,
    argv: &[String],
    dir: Option<String>,
    tty: bool,
    stdin: Stdin,
    user: Option<String>,
    extra: &[(String, String)],
) -> Result<vk_core::messages::CmdResult> {
    plan.require_resolved()?;
    let entry = crate::vms::resolve_one(Some(&plan.state_dir))?;
    let addr: vk_core::addr::SocketAddr = entry.exec_addr.parse()?;
    let env: Vec<String> = plan
        .exec_env
        .iter()
        .map(|e| format!("{}={}", e.name, e.value))
        .chain(extra.iter().map(|(k, v)| format!("{k}={v}")))
        .collect();
    let (program, rest) = argv.split_first().context("empty command")?;
    crate::exec::run(
        addr,
        false,
        false,
        env,
        dir.or_else(|| plan.workspace_folder.clone()),
        tty,
        user.or_else(|| plan.user.clone()),
        program.clone(),
        rest.to_vec(),
        stdin,
    )
    .await
}

/// What the dev tooling runs in the environment on its own account — a hook, a task, the
/// editor's reconcile step — as the config's user.
pub async fn exec_in_guest(
    plan: &Plan,
    argv: &[String],
    dir: Option<String>,
    tty: bool,
    stdin: Stdin,
) -> Result<vk_core::messages::CmdResult> {
    exec_with(plan, argv, dir, tty, stdin, None, &[]).await
}

/// [`exec_in_guest`], with `extra` on top of `exec-env` — what an operation tells the
/// command about itself, such as the editor server it selected.
pub async fn exec_in_guest_with(
    plan: &Plan,
    argv: &[String],
    dir: Option<String>,
    tty: bool,
    stdin: Stdin,
    extra: &[(String, String)],
) -> Result<vk_core::messages::CmdResult> {
    exec_with(plan, argv, dir, tty, stdin, None, extra).await
}

/// `vk dev exec`: a session in the primary — as `user` when given, else the config's user —
/// with the plan's `exec-env`, reading this process's stdin.
pub async fn exec_session(
    plan: &Plan,
    argv: &[String],
    dir: Option<String>,
    tty: bool,
    user: Option<String>,
) -> Result<vk_core::messages::CmdResult> {
    exec_with(plan, argv, dir, tty, Stdin::Forward, user, &[]).await
}

/// `vk dev exec --service`: a command in a compose service of the running environment. The
/// service is its own guest, so nothing of the primary's contract applies — no `exec-env`,
/// no `user`, no workspace directory — only what the caller passes. Does not boot anything:
/// a service that is not running is an error, as is an environment that is down.
pub async fn exec_in_service(
    plan: &Plan,
    service: &str,
    argv: &[String],
    dir: Option<String>,
    tty: bool,
    user: Option<String>,
) -> Result<vk_core::messages::CmdResult> {
    let entry = running_entry(plan)?;
    let addr = crate::vms::service_exec_addr(&entry, service)?;
    let (program, rest) = argv.split_first().context("empty command")?;
    crate::exec::run(
        addr,
        false,
        false,
        Vec::new(),
        dir,
        tty,
        user,
        program.clone(),
        rest.to_vec(),
        Stdin::Forward,
    )
    .await
}

/// This plan's running VM, or an error that says it is down and how to bring it up.
fn running_entry(plan: &Plan) -> Result<crate::vms::VmEntry> {
    running_vm(plan).ok_or_else(|| {
        anyhow::anyhow!(
            "the dev environment is not running ({}) — `vk dev up` boots it",
            plan.state_dir.display()
        )
    })
}

/// The guest directory that stands for the caller's: their working directory mapped into
/// the workspace folder when it lies inside the checkout, the workspace folder itself
/// otherwise.
pub fn guest_cwd(plan: &Plan) -> Option<String> {
    let folder = plan.workspace_folder.as_deref()?;
    let cwd = std::env::current_dir().ok()?;
    let cwd = std::fs::canonicalize(&cwd).unwrap_or(cwd);
    match cwd.strip_prefix(&plan.workspace) {
        Ok(rel) if rel.as_os_str().is_empty() => Some(folder.to_string()),
        Ok(rel) => Some(format!("{folder}/{}", rel.to_string_lossy())),
        Err(_) => Some(folder.to_string()),
    }
}

/// `vk dev shell`: the environment's own login shell, on a terminal. `$SHELL` is what the
/// image says the user's shell is; a login shell so their profile runs, as opening a
/// terminal in the editor would.
pub const LOGIN_SHELL: [&str; 3] = ["sh", "-lc", "exec \"${SHELL:-/bin/sh}\" -l"];

/// What a stop did, and whether it left the environment down.
pub struct Stopped {
    /// what to print: one line per VM stopped, or why there was nothing to stop
    pub report: String,
    /// nothing of this environment is running any more — the state the caller asked for
    pub all_down: bool,
}

/// `vk dev stop`: stop the environment (and, with it, its publishers).
pub fn stop(plan: &Plan, timeout: u64) -> Result<Stopped> {
    // Stopping what is already stopped is the state asked for, not a failure — a script
    // that ends a session need not know whether the VM outlived it. Relays cannot outlive
    // the VM, but their records can; clear those too.
    if running_vm(plan).is_none() {
        crate::publish::stop_all_quietly(&plan.state_dir, Duration::from_secs(5));
        return Ok(Stopped {
            report: format!(
                "dev environment not running ({})\n",
                plan.state_dir.display()
            ),
            all_down: true,
        });
    }
    let (report, all_down) = crate::vms::stop_cmd(
        Some(crate::vms::Selector::Dir(plan.state_dir.clone())),
        false,
        timeout,
    )?;
    Ok(Stopped { report, all_down })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::boot::ensure_state_dir;
    use crate::dev::plan::EnvVar;
    use crate::dev::testutil::{plan_in, scratch};

    fn env(name: &str, value: &str) -> EnvVar {
        EnvVar {
            name: name.into(),
            value: value.into(),
            sensitive: false,
        }
    }

    #[test]
    fn the_session_env_is_one_line_per_variable_and_names_what_it_cannot_write() {
        let (text, skipped) = session_env_text(&[env("PATH", "/opt/bin:/usr/bin"), env("N", "")]);
        assert_eq!(text, "PATH=/opt/bin:/usr/bin\nN=\n");
        assert!(skipped.is_empty());
        assert_eq!(session_env_text(&[]), (String::new(), Vec::new()));

        // The file is line-oriented, so a newline cannot be expressed — and the variable it
        // would have silently truncated is named rather than dropped in silence.
        let (text, skipped) = session_env_text(&[
            env("GOOD", "one"),
            env("MULTI", "a\nb"),
            env("ODD\nNAME", "x"),
        ]);
        assert_eq!(text, "GOOD=one\n");
        assert_eq!(skipped, ["MULTI", "ODD\\nNAME"]);
    }

    /// `after_boot` in the parent, against a state dir with and without the note the child
    /// leaves: the identity is written for a fresh boot and never for a reuse. Nothing here
    /// reaches a guest — no endpoints, no hooks, and an unresolved variable keeps
    /// `sync_session_env` from trying.
    #[tokio::test]
    async fn the_identity_is_written_for_a_boot_and_never_for_a_reuse() {
        let t = scratch("after-boot");
        let mut plan = plan_in(&t.0);
        plan.unresolved = vec!["${localEnv:TOKEN} is not set".into()];
        ensure_state_dir(&plan).unwrap();
        let identity = plan.state_dir.join("dev.json");
        // The note `boot` leaves for its own parent, in the shape `boot::note_transition`
        // writes it — verb, child pid, this invocation's nonce; this is the process that
        // would read it.
        let note = plan
            .state_dir
            .join(format!(".transition.{}", std::process::id()));
        let booted = format!("booted 31337 {}\n", crate::detach::boot_nonce());

        // No note: whatever is running was not booted by this invocation, so its recorded
        // identity is left exactly as it is.
        after_boot(&plan).await.unwrap();
        assert!(
            !identity.exists(),
            "a reuse must not relabel the environment"
        );

        std::fs::write(&note, &booted).unwrap();
        after_boot(&plan).await.unwrap();
        assert!(!note.exists(), "the note is consumed");
        let recorded: crate::dev::Identity =
            serde_json::from_slice(&std::fs::read(&identity).unwrap()).unwrap();
        assert_eq!(recorded.created_by, own_version());
        let (digest, _) = identity_of(&plan, None).unwrap();
        assert_eq!(recorded.digest, digest);

        // And the note is not re-read: a second attach leaves that identity in place.
        std::fs::remove_file(&identity).unwrap();
        after_boot(&plan).await.unwrap();
        assert!(!identity.exists());
    }
}
