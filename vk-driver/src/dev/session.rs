//! Sessions in a running environment (`exec`, `shell`, `ssh`), plus `after_boot` and `stop`.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use vk_core::exec::client::Stdin;

use crate::dev::plan::{Plan, Source};

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

/// Everything that happens once the guest is up: the session environment, the endpoints,
/// `hooks.create` and `hooks.start`, and recording what was booted. Runs in the parent (see
/// the module docs).
///
/// The identity file is written *last*, once every readiness step has succeeded — the
/// session environment, the endpoints and `hooks.create`/`hooks.start`. It is what a joining
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
        // to a start do not run, and the session change applied above is not recorded, so
        // `vk dev status` keeps reporting it as drift until a restart records the new
        // identity. Endpoints are the exception: `plan --diff` calls an endpoint edit
        // host-side, applied without a restart, which holds only if the relays that no
        // longer match go first.
        reconcile_publishers(plan);
        return publish_endpoints(plan).await;
    }
    let (digest, manifest) = identity_of(plan, booted_wrapper_digest(plan).as_deref())?;
    // What was actually booted, read off the registry entry the boot filed. `None` where
    // there is no entry to read it from, which leaves the creation hook unstamped rather
    // than stamped with something that describes nothing.
    let generation = running_vm(plan).map(|vm| generation_of(plan, &root_identity(plan, &vm)));
    publish_endpoints(plan).await?;
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

/// Serialize `exec-env` for the guest's SSH server as one `NAME=value` per line. Skip names
/// or values containing newlines and return their names so the caller can report variables
/// that would otherwise silently disappear from SSH sessions.
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
    // `$$`-keyed tmp: two attaches racing to sync must not write the same scratch file and
    // publish a half-written interleaving of each other's text. The rename stays atomic.
    let script = "umask 077 && t=\"$1.$$.tmp\" && printf %s \"$VK_SESSION_ENV\" >\"$t\" && mv -f \"$t\" \"$1\"";
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

/// Stop the publishers an attach can no longer stand behind: one whose endpoint has gone
/// from the config, and one whose listen address or target has moved. `publish::ensure`
/// refuses to replace a same-named publisher that runs a different spec, so without this an
/// endpoint edit — which `vk dev plan --diff` calls host-side, applied by the next `up`
/// without a restart — would fail on a required endpoint and be ignored on an optional one.
///
/// Best effort: a registry that cannot be read leaves the relays alone, and `ensure` then
/// reports whatever it runs into.
fn reconcile_publishers(plan: &Plan) {
    let live = crate::publish::live(&plan.state_dir).unwrap_or_default();
    if live.is_empty() {
        return;
    }
    // The remembered allocation, never a fresh one: an `auto` endpoint that has no address
    // yet has nothing running for it either.
    let alloc = crate::dev::endpoints::load(plan).unwrap_or_else(|e| {
        eprintln!("virtkit: the endpoints' relays were left alone: {e:#}");
        None
    });
    for (entry, _) in live {
        let ep = plan.endpoints.iter().find(|e| e.name == entry.name);
        // The endpoint's listen address in the normalized spelling `publish` recorded, so the
        // comparison is like for like rather than raw string against normalized. `None` for
        // an `auto` endpoint that has no address yet — nothing to compare.
        let wanted = ep.and_then(|ep| {
            crate::dev::endpoints::address_of(alloc.as_ref(), ep)
                .map(|a| crate::dev::endpoints::listen_on(ep, &a))
                .and_then(|l| l.parse::<vk_core::addr::SocketAddr>().ok())
                .map(|l| l.to_string())
        });
        let Some(reason) = stale_reason(&entry, ep, wanted.as_deref()) else {
            continue;
        };
        eprintln!(
            "virtkit: endpoint {}: {reason} — stopping its relay",
            entry.name
        );
        if let Err(e) =
            crate::publish::stop(&plan.state_dir, Some(&entry.name), Duration::from_secs(5))
        {
            eprintln!("virtkit: endpoint {}: {e:#}", entry.name);
        }
    }
}

/// Report a removed endpoint or changed target or listen address; return `None` for a match.
/// `wanted_listen` uses `publish`'s normalized spelling. For an unallocated `auto` endpoint
/// it is `None`, so only the target is compared.
///
/// Match records to endpoints by name, not by `service`: the record's `service` is the
/// `--via` dialer, which dev endpoints never set because the primary dials all endpoints,
/// including service endpoints. Comparing it to the endpoint's owner would stop every
/// service relay on every reattach.
fn stale_reason(
    entry: &crate::publish::Entry,
    ep: Option<&crate::dev::plan::EndpointPlan>,
    wanted_listen: Option<&str>,
) -> Option<&'static str> {
    match ep {
        None => Some("it is no longer in the config"),
        Some(ep) if entry.to != ep.to => Some("what it forwards to has changed"),
        Some(_) => match wanted_listen {
            Some(w) if w != entry.listen => Some("where it listens has changed"),
            _ => None,
        },
    }
}

/// Publish the config's endpoints. One that cannot be published is reported and the rest
/// still are — the environment is up, and losing one optional endpoint should not read as a
/// failed `up`; a required one is what the environment is for, so its failure is the
/// operation's.
/// After a boot or an attach: the primary's endpoints, and those of every service the
/// manager reports running — a relay that died, or a `vk` that was upgraded under a running
/// environment, is re-published. A required primary endpoint that
/// cannot be published leaves the environment not ready.
async fn publish_endpoints(plan: &Plan) -> Result<()> {
    if plan.endpoints.is_empty() {
        return Ok(());
    }
    let entry = crate::vms::resolve_one(Some(&plan.state_dir)).context("publishing endpoints")?;
    let running: Vec<String> = match crate::vms::control_socket(&entry) {
        Some(ctl) => crate::vms::control(
            &ctl,
            &vk_core::fleetctl::Request::List,
            Some(std::time::Duration::from_secs(5)),
            |_| {},
        )
        .map(|r| {
            r.units
                .into_iter()
                .filter(|u| u.state == "running")
                .map(|u| u.name)
                .collect()
        })
        .unwrap_or_default(),
        None => Vec::new(),
    };
    let failed = publish_for(plan, &entry, None).await?;
    for service in running {
        if plan
            .endpoints
            .iter()
            .any(|e| e.service.as_deref() == Some(&*service))
        {
            // A service's required endpoint failing does not un-ready the environment; it is
            // reported, and `vk dev service up` on that service says so in its own terms.
            let _ = publish_for(plan, &entry, Some(&service)).await;
        }
    }
    if !failed.is_empty() {
        bail!(
            "required endpoint(s) not published, so the environment is not ready:\n  {}",
            failed.join("\n  ")
        );
    }
    Ok(())
}

/// Publish the endpoints of `service` (the primary for `None`), allocating their host
/// address first. Prints each URL or address as it comes up. Returns the required endpoints
/// that failed, one message each; optional failures are reported here and forgotten.
async fn publish_for(
    plan: &Plan,
    entry: &crate::vms::VmEntry,
    service: Option<&str>,
) -> Result<Vec<String>> {
    let mine: Vec<&crate::dev::plan::EndpointPlan> = plan
        .endpoints
        .iter()
        .filter(|e| e.service.as_deref() == service)
        .collect();
    if mine.is_empty() {
        return Ok(Vec::new());
    }
    let addr: vk_core::addr::SocketAddr = entry.exec_addr.parse()?;
    let live = !crate::publish::live(&plan.state_dir)
        .unwrap_or_default()
        .is_empty();
    let auto_address = if mine.iter().any(|e| e.auto()) {
        Some(
            crate::dev::endpoints::allocate(plan, service, live)
                .context("allocating the endpoints' host address")?
                .to_string(),
        )
    } else {
        None
    };
    let mut failed = Vec::new();
    for ep in mine {
        let address = if ep.auto() {
            auto_address.clone().expect("allocated above")
        } else {
            crate::dev::endpoints::require_bindable(&ep.name, &ep.address)?;
            ep.address.clone()
        };
        let listen = crate::dev::endpoints::listen_on(ep, &address);
        let result = match listen.parse() {
            Ok(l) => {
                crate::publish::ensure(&plan.state_dir, &ep.name, &addr, &l, &ep.to, None).await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(crate::publish::Ensured::Started(e)) => {
                let shown = crate::dev::endpoints::url_on(ep, &address).unwrap_or(e.listen);
                eprintln!("published {}: {shown} -> {}", ep.name, e.to);
            }
            Ok(crate::publish::Ensured::AlreadyRunning(_)) => {}
            Err(e) => {
                // An allocated address that turns out taken is not ours after all: forget
                // this service's octet, so its next publish picks another rather than
                // failing the same way. The block and the other services' octets stay —
                // relays of theirs are already up on them. `forget` keeps the octet, and
                // says so itself, while another of this service's endpoints is still up on
                // it, so only claim it was dropped when it was.
                if ep.auto()
                    && e.downcast_ref::<crate::publish::AddressInUse>().is_some()
                    && crate::dev::endpoints::forget(plan, service)
                {
                    eprintln!(
                        "virtkit: {address} is in use after all — the address remembered for \
                         {} is forgotten; the next publish picks another",
                        service.unwrap_or("the environment")
                    );
                }
                if ep.required {
                    failed.push(format!("{}: {e:#}", ep.name));
                } else {
                    eprintln!("virtkit: endpoint {} (optional): {e:#}", ep.name);
                }
            }
        }
    }
    Ok(failed)
}

/// Stop the publishers of `service`'s endpoints — its relays only, not the environment's.
fn unpublish_for(plan: &Plan, service: &str) {
    for ep in plan
        .endpoints
        .iter()
        .filter(|e| e.service.as_deref() == Some(service))
    {
        // Best effort: a relay that will not stop is reported by the next `ensure`, which
        // refuses to replace a publisher running a different spec.
        let _ = crate::publish::stop(
            &plan.state_dir,
            Some(&ep.name),
            std::time::Duration::from_secs(5),
        );
    }
}

/// Run in the primary as `user` (else the config's), in `dir` (else the workspace folder),
/// with the plan's `exec-env` plus `extra` — the scope the dev tooling runs in, as against
/// the guest's own processes.
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

/// Send one host request to the running environment's service manager, relaying
/// on-demand build progress to stderr. This function boots nothing: `status` and
/// `down` report an absent environment; for `up`, the caller boots it first.
pub async fn service(
    plan: &Plan,
    req: &vk_core::fleetctl::Request,
) -> Result<vk_core::fleetctl::Reply> {
    let entry = running_entry(plan)?;
    let ctl = crate::vms::control_socket(&entry).ok_or_else(|| {
        anyhow::anyhow!(
            "the environment has no compose services (source: {})",
            match &plan.source {
                Source::Compose { file, .. } => file.display().to_string(),
                Source::Image { reference } => format!("image {reference}"),
                Source::Build { dockerfile, .. } => dockerfile.display().to_string(),
            }
        )
    })?;
    // A start may build an image; the others answer promptly, but a stop waits for a guest to
    // power off, so give every op a generous bound rather than none.
    let timeout = match req {
        vk_core::fleetctl::Request::Start { .. } => None,
        _ => Some(std::time::Duration::from_secs(120)),
    };
    // A service's relays go with it: down before the stop, up once the start is confirmed.
    if let vk_core::fleetctl::Request::Stop { unit } = req {
        unpublish_for(plan, unit);
    }
    let result = crate::vms::control(&ctl, req, timeout, |line| eprintln!("{line}"));
    // Restore relays if the manager refuses the stop or the request fails, so a service
    // that remains running stays reachable without waiting for the next attach to republish.
    if let vk_core::fleetctl::Request::Stop { unit } = req
        && !result.as_ref().is_ok_and(|r| r.ok)
    {
        let _ = publish_for(plan, &entry, Some(unit)).await;
    }
    let reply = result?;
    if let vk_core::fleetctl::Request::Start { unit } = req
        && reply.ok
    {
        let failed = publish_for(plan, &entry, Some(unit)).await?;
        if !failed.is_empty() {
            bail!(
                "{unit} is running, but its required endpoint(s) are not published:\n  {}",
                failed.join("\n  ")
            );
        }
    }
    Ok(reply)
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
    // Canonicalize the workspace to match: a symlink component in either would otherwise
    // fail the prefix check and drop the caller at the workspace root rather than their subdir.
    let workspace =
        std::fs::canonicalize(&plan.workspace).unwrap_or_else(|_| plan.workspace.clone());
    match cwd.strip_prefix(&workspace) {
        // A path the guest cannot spell (non-UTF-8) falls back to the workspace root rather
        // than a corrupted subdirectory.
        Ok(rel) if !rel.as_os_str().is_empty() => match rel.to_str() {
            Some(rel) => Some(format!("{folder}/{rel}")),
            None => Some(folder.to_string()),
        },
        _ => Some(folder.to_string()),
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

    fn endpoint(name: &str, service: Option<&str>, to: &str) -> crate::dev::plan::EndpointPlan {
        crate::dev::plan::EndpointPlan {
            name: name.into(),
            service: service.map(String::from),
            host_port: 8443,
            address: "auto".into(),
            listen: "tcp://auto:8443".into(),
            to: to.into(),
            scheme: None,
            path: None,
            required: false,
        }
    }

    fn entry(name: &str, listen: &str, to: &str) -> crate::publish::Entry {
        crate::publish::Entry {
            name: name.into(),
            listen: listen.into(),
            to: to.into(),
            service: None,
            pid: 0,
            created_secs: 0,
        }
    }

    #[test]
    fn a_service_relay_that_still_matches_survives_a_reattach() {
        // A compose-service endpoint publishes with no `--via` — the primary dials it — so
        // its record's `service` is None while the endpoint's owning service is Some. The
        // relay still forwards exactly where it should, so nothing about it is stale;
        // comparing the two `service`s would stop every service relay on every reattach.
        let ep = endpoint("runner.https", Some("runner"), "tcp://runner:443");
        let live = entry("runner.https", "tcp://127.0.20.1:8443", "tcp://runner:443");
        let wanted = Some("tcp://127.0.20.1:8443");
        assert_eq!(stale_reason(&live, Some(&ep), wanted), None);

        // A changed forward target, listen address, or a dropped endpoint each stop it.
        let moved_to = entry("runner.https", "tcp://127.0.20.1:8443", "tcp://runner:8443");
        assert_eq!(
            stale_reason(&moved_to, Some(&ep), wanted),
            Some("what it forwards to has changed")
        );
        assert_eq!(
            stale_reason(&live, Some(&ep), Some("tcp://127.0.20.2:8443")),
            Some("where it listens has changed")
        );
        assert_eq!(
            stale_reason(&live, None, None),
            Some("it is no longer in the config")
        );
        // An auto endpoint with no address yet cannot have its listen compared — only its
        // target — so a matching target leaves it alone.
        assert_eq!(stale_reason(&live, Some(&ep), None), None);
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
