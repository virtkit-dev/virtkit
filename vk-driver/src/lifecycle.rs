//! Start, stop and restart VMs and compose services by reference. Dev environments use
//! `vk dev` with their recorded workspace and config. Runs replay `run.json`. Service
//! requests go to the primary's manager.
//!
//! [`plan`] selects steps from the target and its primary's state. [`execute`] applies them.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::vmlist::Kind;
use crate::vms::{self, Ref, Selector, VmEntry};

/// What a verb's caller says beside its REFs.
#[derive(Debug, Clone, Copy)]
pub struct Opts<'a> {
    /// the global `--config`, passed on to the `vk dev` a dev environment goes through
    pub config: Option<&'a Path>,
    /// seconds to wait for VM shutdown or for each socket operation during a service stop
    pub timeout: u64,
}

/// A VM a lifecycle verb acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// the VM's name (the primary's, for a service)
    pub name: String,
    pub dir: PathBuf,
    /// `Dev` or `Run`: what the VM — the primary, for a service — is
    pub kind: Kind,
    pub service: Option<String>,
}

impl Target {
    fn shown(&self) -> String {
        match &self.service {
            Some(s) => format!("{}/{s}", self.name),
            None => self.name.clone(),
        }
    }
}

/// A named VM a directory REF could mean.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    name: String,
    dir: PathBuf,
    kind: Kind,
    /// a dev environment's environment name
    environment: Option<String>,
}

/// The one VM of `found` a directory REF means, `None` when there is none. A REF is one VM
/// at most: with several, the project's own VM, its `dev` environment, if that settles it —
/// what `vk dev up` in that directory would start; anything else is refused with their names.
fn pick_one(mut found: Vec<Candidate>, what: &str) -> Result<Option<Candidate>> {
    if found.len() <= 1 {
        return Ok(found.pop());
    }
    let mut devs = found
        .iter()
        .filter(|c| c.kind == Kind::Dev && c.environment.as_deref().unwrap_or("dev") == "dev");
    if let (Some(dev), None) = (devs.next(), devs.next()) {
        return Ok(Some(dev.clone()));
    }
    let names: Vec<&str> = found.iter().map(|c| c.name.as_str()).collect();
    bail!(
        "{} VMs are of {what}: {} — name one",
        found.len(),
        names.join(", ")
    )
}

/// [`vms::kind_of`], against the dev base.
fn kind_of(dir: &Path) -> Result<Kind> {
    let dev_base = crate::dev::plan::dev_state_base().map(|b| vms::canonical(&b))?;
    Ok(vms::kind_of(dir, Some(&dev_base)))
}

/// Find named VMs and unnamed dev environments, running or stopped. An exact state
/// directory match takes precedence over project matches. Unnamed dev environments
/// use their state directory's name.
fn named_at(idx: &crate::names::Index, dir: &Path) -> Result<Vec<Candidate>> {
    let named = idx.all();
    let unnamed = crate::dev::list::unnamed_dirs(&named)?;
    let known: Vec<(String, PathBuf)> = named
        .into_iter()
        .chain(unnamed.into_iter().map(|(name, dir, _)| (name, dir)))
        .filter(|(_, state_dir)| state_dir.is_dir())
        .collect();
    let candidate = |name: &str, state_dir: &Path| -> Result<(Candidate, Option<PathBuf>)> {
        let kind = kind_of(state_dir)?;
        let last = vms::last_entry(state_dir).ok().flatten();
        let (project, environment) = vms::project_of(state_dir, kind, last.as_ref());
        let c = Candidate {
            name: name.to_string(),
            dir: state_dir.to_path_buf(),
            kind,
            environment,
        };
        Ok((c, project))
    };
    // A state dir is its own VM's, whatever project another one records.
    if let Some((name, state_dir)) = known.iter().find(|(_, d)| vms::canonical(d) == dir) {
        return Ok(vec![candidate(name, state_dir)?.0]);
    }
    let mut found = Vec::new();
    for (name, state_dir) in &known {
        let (c, project) = candidate(name, state_dir)?;
        if project.is_some_and(|p| vms::canonical(&p) == dir) {
            found.push(c);
        }
    }
    Ok(found)
}

/// Resolve a REF to one VM, running or not: a name or `NAME/SERVICE`; a state directory, or
/// a project directory, which means the project's VM and never its compose services; or
/// the pid of a running VM. Read as every VM command reads it
/// ([`vms::Selector::from_ref`]), so a word means the same VM to `start` as to `stop`.
pub fn resolve(arg: &OsStr) -> Result<Target> {
    let (sel, service) = Selector::from_ref(Ref::parse(arg)?, false)?;
    // A service is reached only through its running VM, so `PID/SERVICE` needs no name.
    let unnamed = service.is_some();
    resolve_selected(sel, service, unnamed)
}

/// [`resolve`] for a REF already read. `unnamed` takes a running VM without a name by its
/// pid, for what acts on it only while it runs: it is not known once it stops.
pub fn resolve_selected(sel: Selector, service: Option<String>, unnamed: bool) -> Result<Target> {
    let idx = crate::names::Index::open()?;
    let known = match &sel {
        Selector::Named { name, dir } => Some(Candidate {
            name: idx.name_of(dir).unwrap_or_else(|| name.clone()),
            kind: kind_of(dir)?,
            environment: None,
            dir: dir.clone(),
        }),
        Selector::Dir { dir, .. } => {
            let dir = vms::canonical(dir);
            pick_one(named_at(&idx, &dir)?, &dir.display().to_string())?
        }
        Selector::Here { .. } => {
            let dir = vms::canonical(Path::new("."));
            pick_one(named_at(&idx, &dir)?, &dir.display().to_string())?
        }
        Selector::Pid(_) => None,
    };
    let (name, dir, kind) = match known {
        Some(c) => (c.name, c.dir, c.kind),
        // Nothing named there: a running VM still answers to its pid or its directory.
        None => {
            let entry = vms::one_running(Some(sel))?;
            let kind = kind_of(&entry.state_dir)?;
            // A dev environment that has no name yet goes by its state dir's own.
            let own = entry
                .state_dir
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|_| kind == Kind::Dev);
            let name = match idx.name_of(&entry.state_dir).or(own.map(str::to_string)) {
                Some(name) => name,
                None if unnamed => entry.pid.to_string(),
                None => bail!(
                    "the VM {} has no name: it is not known once it stops (`vk stop {}`)",
                    entry.pid,
                    entry.pid
                ),
            };
            (name, entry.state_dir, kind)
        }
    };
    Ok(Target {
        name,
        dir,
        kind,
        service,
    })
}

/// The running VM on `dir`, if any.
fn running_on(dir: &Path) -> Option<VmEntry> {
    let dir = vms::canonical(dir);
    vms::running().into_iter().find(|e| e.state_dir == dir)
}

/// One step of a start or a stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `vk dev --workspace W --environment E up`
    DevUp,
    /// `vk dev … service up|down S`
    DevService { up: bool },
    /// replay `run.json`
    Replay,
    /// a `Start`/`Stop` to the run's service manager
    Control { up: bool },
    /// stop the VM on the target's state dir — that one alone — and what it publishes
    StopVm,
    /// say so and do nothing
    Nothing(String),
}

/// A start or a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Start,
    Stop,
}

/// Starting a service may boot its primary. Stopping a target whose primary is down fails.
pub fn plan(verb: Verb, t: &Target, primary_up: bool) -> Result<Vec<Step>> {
    use Step::*;
    let dev = t.kind == Kind::Dev;
    let boot = if dev { DevUp } else { Replay };
    let shown = t.shown();
    Ok(match (verb, &t.service) {
        (Verb::Start, None) if primary_up => vec![Nothing(format!("{shown} is running"))],
        (Verb::Start, None) => vec![boot],
        (Verb::Start, Some(_)) => {
            let mut steps = Vec::new();
            if !primary_up {
                steps.push(boot);
            }
            steps.push(if dev {
                DevService { up: true }
            } else {
                Control { up: true }
            });
            steps
        }
        (Verb::Stop, None) if !primary_up => bail!("{shown} is not running (`vk start {shown}`)"),
        (Verb::Stop, None) => vec![StopVm],
        (Verb::Stop, Some(_)) if !primary_up => {
            bail!("{shown} is not running: its VM {} is down", t.name)
        }
        // Its manager says whether it ran, and refuses a service it does not know.
        (Verb::Stop, Some(_)) => vec![if dev {
            DevService { up: false }
        } else {
            Control { up: false }
        }],
    })
}

/// Select the recorded workspace, environment and optional `--dev-config` from `dev.json`.
/// The config may be outside the workspace.
fn dev_selection(dir: &Path) -> Result<Vec<OsString>> {
    let identity = recorded_identity(dir)?;
    let text = |key: &str| identity.manifest.get(key).and_then(|v| v.as_str());
    let workspace = text("workspace").context("its dev.json records no workspace")?;
    if !Path::new(workspace).is_dir() {
        bail!("its workspace {workspace} is gone");
    }
    if let Some(config) = text("config").filter(|c| !Path::new(c).is_file()) {
        bail!("its config {config} is gone");
    }
    Ok(selection_args(
        workspace,
        text("config"),
        text("environment").unwrap_or("dev"),
    ))
}

/// The identity the dev environment on `dir` recorded in its `dev.json`.
fn recorded_identity(dir: &Path) -> Result<crate::dev::Identity> {
    let path = dir.join("dev.json");
    serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("reading {}", path.display()))
}

/// Older identities omit the config path. Let `vk dev` find the workspace config then.
fn selection_args(workspace: &str, config: Option<&str>, environment: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["dev".into(), "--workspace".into(), workspace.into()];
    if let Some(config) = config {
        args.extend(["--dev-config".into(), config.into()]);
    }
    args.extend(["--environment".into(), environment.into()]);
    args
}

/// [`dev_selection`] after the global `--config` this `vk` was given, if any.
fn dev_args(dir: &Path, o: Opts) -> Result<Vec<OsString>> {
    let mut args = Vec::new();
    if let Some(config) = o.config {
        let config = std::path::absolute(config).context("resolving --config")?;
        args.extend(["--config".into(), config.into_os_string()]);
    }
    args.extend(dev_selection(dir)?);
    Ok(args)
}

/// Validate the recorded `vk run` and its detached replay with the CLI parser.
/// `-t` and `--shell` require a terminal. Return the replay arguments and working directory.
fn replay(t: &Target) -> Result<(Vec<OsString>, PathBuf)> {
    let Some(recipe) = crate::names::Recipe::read(&t.dir)? else {
        bail!(
            "{} recorded no way to run it again (no {}): run it with `vk run` once more",
            t.name,
            crate::names::RECIPE
        );
    };
    let parse = |args: &[OsString]| {
        <crate::Cli as clap::Parser>::try_parse_from(
            std::iter::once(OsString::from("vk")).chain(args.iter().cloned()),
        )
    };
    // Neither message quotes the command line: it holds `--password`, if one was given.
    match parse(&recipe.args) {
        Ok(crate::Cli {
            cmd: crate::Cmd::Run { tty, shell, .. },
            ..
        }) if tty || shell => bail!(
            "{} was run with {}, which needs a terminal: `vk start` runs it in the background \
             — run it with `vk run` again",
            t.name,
            if shell { "--shell" } else { "-t" }
        ),
        Ok(crate::Cli {
            cmd: crate::Cmd::Run { .. },
            ..
        }) => {}
        Ok(_) => bail!("{}'s {} records no `vk run`", t.name, crate::names::RECIPE),
        Err(e) => bail!(
            "{}'s {} no longer reads as a `vk run` ({:?})",
            t.name,
            crate::names::RECIPE,
            e.kind()
        ),
    }
    let args = recipe.replay_args(&t.dir, &t.name);
    match parse(&args) {
        Ok(crate::Cli {
            config,
            cmd:
                crate::Cmd::Run {
                    detach: true,
                    state_dir: Some(dir),
                    name: Some(name),
                    ..
                },
        }) if dir == t.dir && name == t.name => {
            if !recipe.cwd.is_dir() {
                bail!(
                    "{}'s working directory {} is gone",
                    t.name,
                    recipe.cwd.display()
                );
            }
            // Relative to the working directory, where the replay reads it.
            if let Some(config) = config.filter(|c| !recipe.cwd.join(c).is_file()) {
                bail!("{}'s config {} is gone", t.name, config.display());
            }
            Ok((args, recipe.cwd))
        }
        _ => bail!(
            "{}'s {} cannot be run again in the background",
            t.name,
            crate::names::RECIPE
        ),
    }
}

/// Before stopping a primary, check its dev workspace and recorded config or validate
/// its detached run recipe, working directory and recorded `--config`.
fn startable(t: &Target, steps: &[Step]) -> Result<()> {
    for step in steps {
        match step {
            Step::DevUp => {
                dev_selection(&t.dir).with_context(|| format!("cannot start {}", t.name))?;
            }
            Step::Replay => {
                replay(t)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Run this `vk` with `args`, in `cwd`, its output ours; fail unless it succeeds, saying
/// that `what` did not happen.
fn vk(what: &str, args: &[OsString], cwd: Option<&Path>, from_recipe: bool) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the running vk")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    if from_recipe {
        cmd.env(crate::FROM_RECIPE_ENV, "1");
    }
    succeeds(cmd, what)
}

/// Report the child status and operation. The child inherits stderr, and its arguments
/// may contain `--password`.
fn succeeds(mut cmd: std::process::Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("{what}: running vk"))?;
    if !status.success() {
        bail!("{what}: vk {status}");
    }
    Ok(())
}

/// Return the service manager's reply, or its error with the service name. For stops,
/// `timeout` bounds each socket read and write in seconds.
fn control_unit(ctl: &Path, shown: &str, unit: &str, up: bool, timeout: u64) -> Result<String> {
    let req = match up {
        true => vk_core::fleetctl::Request::Start { unit: unit.into() },
        false => vk_core::fleetctl::Request::Stop { unit: unit.into() },
    };
    let timeout = (!up).then(|| Duration::from_secs(timeout));
    let reply = vms::control(ctl, &req, timeout, |line| eprintln!("{line}"))
        .with_context(|| format!("{shown}: asking its VM's service manager"))?;
    if !reply.ok {
        bail!("{shown}: {}", reply.message);
    }
    Ok(reply.message)
}

/// Carry out `steps` on `t`.
fn execute(t: &Target, steps: &[Step], o: Opts) -> Result<String> {
    let mut out = String::new();
    for step in steps {
        match step {
            Step::Nothing(what) => out.push_str(&format!("{what}\n")),
            Step::DevUp => {
                let mut args =
                    dev_args(&t.dir, o).with_context(|| format!("cannot start {}", t.name))?;
                args.push("up".into());
                vk(&format!("starting {}", t.name), &args, None, false)?;
            }
            Step::DevService { up } => {
                let mut args = dev_args(&t.dir, o)?;
                let service = t.service.clone().unwrap_or_default();
                let op = if *up { "up" } else { "down" };
                args.extend(["service".into(), op.into(), service.into()]);
                if !up {
                    args.extend(["--timeout".into(), o.timeout.to_string().into()]);
                }
                let what = if *up { "starting" } else { "stopping" };
                vk(&format!("{what} {}", t.shown()), &args, None, false)?;
            }
            Step::Replay => {
                let (args, cwd) = replay(t)?;
                vk(&format!("starting {}", t.name), &args, Some(&cwd), true)?;
            }
            Step::Control { up } => {
                let entry =
                    running_on(&t.dir).with_context(|| format!("{} is not running", t.name))?;
                let ctl = vms::control_socket(&entry)
                    .with_context(|| format!("{} runs no compose services", t.name))?;
                let unit = t.service.clone().unwrap_or_default();
                let said = control_unit(&ctl, &t.shown(), &unit, *up, o.timeout)?;
                out.push_str(&format!("{said}\n"));
            }
            Step::StopVm => {
                // That VM alone: a directory selector would also take one whose project
                // this state dir is.
                let Some(entry) = running_on(&t.dir) else {
                    out.push_str(&format!("{} is not running\n", t.name));
                    continue;
                };
                let (line, down) = vms::stop_entry(&entry, o.timeout)
                    .with_context(|| format!("{} is held by another run", t.name))?;
                out.push_str(&line);
                if !down {
                    bail!("{out}");
                }
            }
        }
    }
    Ok(out)
}

/// `vk start` on each REF in turn; the exit status says whether every one started.
pub fn start(refs: &[OsString], o: Opts) -> ExitCode {
    let mut ok = true;
    for r in refs {
        // A project directory means its own VM: one REF starts one VM at most.
        let result = resolve(r).and_then(|t| {
            let steps = plan(Verb::Start, &t, running_on(&t.dir).is_some())?;
            execute(&t, &steps, o)
        });
        ok &= report(result);
    }
    exit(ok)
}

/// `vk stop` of a REF already read that names a VM or a compose service: through its kind.
/// A running VM without a name goes by its pid. One that is not running exits 1.
pub fn stop(sel: Selector, service: Option<String>, o: Opts) -> ExitCode {
    let result = resolve_selected(sel, service, true).and_then(|t| {
        let up = running_on(&t.dir).is_some();
        if !up && t.kind == Kind::Dev && t.service.is_none() {
            // What an environment published can outlive it on record: cleared, as
            // `vk dev stop` does for one already down.
            crate::publish::stop_all_quietly(&t.dir, Duration::from_secs(5));
        }
        execute(&t, &plan(Verb::Stop, &t, up)?, o)
    });
    exit(report(result))
}

/// Print what a verb did, or why it failed; whether it succeeded.
fn report(result: Result<String>) -> bool {
    match result {
        Ok(report) => crate::write_report(&report) == ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vk: {e:#}");
            false
        }
    }
}

/// The exit status for whether everything went through.
fn exit(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Restart each REF in order. Continue after failures and return 1 if any failed.
pub fn restart(refs: &[OsString], o: Opts) -> ExitCode {
    let mut ok = true;
    for r in refs {
        let result = resolve(r).and_then(|t| restart_one(&t, o));
        ok &= report(result);
    }
    exit(ok)
}

/// Keep the resolved target across the stop. Check the primary's boot inputs before
/// stopping it, and skip the stop when the primary is down.
fn restart_one(t: &Target, o: Opts) -> Result<String> {
    let up = running_on(&t.dir).is_some();
    // A service's VM stays up across the service's restart.
    startable(t, &plan(Verb::Start, t, up && t.service.is_some())?)?;
    let mut out = String::new();
    if up {
        out.push_str(&execute(t, &plan(Verb::Stop, t, true)?, o)?);
    }
    let steps = plan(Verb::Start, t, running_on(&t.dir).is_some())?;
    out.push_str(&execute(t, &steps, o)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(kind: Kind, service: Option<&str>) -> Target {
        Target {
            name: "app".into(),
            dir: "/s/app".into(),
            kind,
            service: service.map(Into::into),
        }
    }

    fn steps(verb: Verb, kind: Kind, service: Option<&str>, up: bool) -> Vec<Step> {
        plan(verb, &target(kind, service), up).unwrap()
    }

    #[test]
    fn start_boots_by_kind_and_a_service_after_its_primary() {
        use Step::*;
        assert_eq!(steps(Verb::Start, Kind::Dev, None, false), [DevUp]);
        assert_eq!(steps(Verb::Start, Kind::Run, None, false), [Replay]);
        assert!(matches!(
            steps(Verb::Start, Kind::Run, None, true)[..],
            [Nothing(_)]
        ));
        assert_eq!(
            steps(Verb::Start, Kind::Dev, Some("db"), false),
            [DevUp, DevService { up: true }]
        );
        assert_eq!(
            steps(Verb::Start, Kind::Run, Some("db"), true),
            [Control { up: true }]
        );
    }

    /// Stopping a primary targets only that VM. Its manager handles service stops.
    /// Both targets fail when the primary is down.
    #[test]
    fn stop_stops_the_one_vm_and_refuses_what_is_down() {
        use Step::*;
        assert_eq!(steps(Verb::Stop, Kind::Dev, None, true), [StopVm]);
        assert_eq!(steps(Verb::Stop, Kind::Run, None, true), [StopVm]);
        assert_eq!(
            steps(Verb::Stop, Kind::Dev, Some("db"), true),
            [DevService { up: false }]
        );
        assert_eq!(
            steps(Verb::Stop, Kind::Run, Some("db"), true),
            [Control { up: false }]
        );
        for (kind, service) in [
            (Kind::Dev, None),
            (Kind::Run, None),
            (Kind::Run, Some("db")),
        ] {
            let err = plan(Verb::Stop, &target(kind, service), false).unwrap_err();
            assert!(err.to_string().contains("is not running"), "{err}");
        }
    }

    /// A dev environment is started through `vk dev` with the config file it was booted
    /// from, when its `dev.json` recorded one.
    #[test]
    fn a_dev_environment_is_selected_with_its_recorded_config() {
        assert_eq!(
            selection_args("/w/shop", Some("/etc/shop.toml"), "test"),
            [
                "dev",
                "--workspace",
                "/w/shop",
                "--dev-config",
                "/etc/shop.toml",
                "--environment",
                "test"
            ]
        );
        assert_eq!(
            selection_args("/w/shop", None, "dev"),
            ["dev", "--workspace", "/w/shop", "--environment", "dev"]
        );
    }

    /// A directory REF is one VM at most: the only one of that project, else its `dev`
    /// environment when that settles it; several are otherwise refused.
    #[test]
    fn a_directory_means_one_vm_and_the_projects_own_among_several() {
        let c = |name: &str, kind: Kind, env: Option<&str>| Candidate {
            name: name.into(),
            dir: format!("/s/{name}").into(),
            kind,
            environment: env.map(Into::into),
        };
        let shop = c("shop", Kind::Dev, Some("dev"));
        let test = c("shop-test", Kind::Dev, Some("test"));
        let tool = c("tool", Kind::Run, None);
        assert_eq!(pick_one(vec![], "/w").unwrap(), None);
        assert_eq!(
            pick_one(vec![tool.clone()], "/w").unwrap(),
            Some(tool.clone())
        );
        let all = vec![test.clone(), tool.clone(), shop.clone()];
        assert_eq!(pick_one(all, "/w").unwrap(), Some(shop.clone()));
        // No `dev` environment, or two of them: nothing settles it.
        let err = pick_one(vec![test.clone(), tool.clone()], "/w")
            .unwrap_err()
            .to_string();
        assert!(err.contains("2 VMs are of /w: shop-test, tool"), "{err}");
        assert!(pick_one(vec![shop.clone(), shop], "/w").is_err());
    }

    /// A child that fails is reported by what it was for and how it ended, never by its
    /// arguments, which for a replayed run hold whatever its command line held.
    #[test]
    fn a_failed_child_never_shows_its_arguments() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "exit 3", "--password=s3cret-sentinel"]);
        let err = format!("{:#}", succeeds(cmd, "starting app").unwrap_err());
        assert!(!err.contains("s3cret-sentinel"), "{err}");
        assert!(err.contains("starting app") && err.contains('3'), "{err}");
    }

    /// A manager that cannot be asked, and one that refuses a unit it does not know, are
    /// errors; what it says when it acts is what `vk` says.
    #[test]
    fn the_service_manager_answers_or_the_service_fails() {
        use std::io::{BufRead, Write};
        let t = crate::dev::testutil::scratch("control");
        let gone = t.0.join("gone.sock");
        let err = control_unit(&gone, "app/db", "db", false, 1).unwrap_err();
        assert!(format!("{err:#}").contains("service manager"), "{err:#}");
        let ctl = t.0.join("ctl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&ctl).unwrap();
        let serve = std::thread::spawn(move || {
            for reply in [
                vk_core::fleetctl::Reply::err("no such unit \"nope\""),
                vk_core::fleetctl::Reply::ok("db already running (10.0.2.3)"),
            ] {
                let (mut conn, _) = listener.accept().unwrap();
                let mut line = String::new();
                std::io::BufReader::new(&conn).read_line(&mut line).unwrap();
                let frame = vk_core::fleetctl::Frame::Done(reply);
                let mut text = serde_json::to_string(&frame).unwrap();
                text.push('\n');
                conn.write_all(text.as_bytes()).unwrap();
            }
        });
        let err = control_unit(&ctl, "app/nope", "nope", false, 5).unwrap_err();
        assert!(err.to_string().contains("app/nope: no such unit"), "{err}");
        let said = control_unit(&ctl, "app/db", "db", true, 5).unwrap();
        assert_eq!(said, "db already running (10.0.2.3)");
        serve.join().unwrap();
    }

    /// A recipe is replayed in the background as the parser reads it back, so one that
    /// needs a terminal is refused before anything is stopped for it.
    #[test]
    fn a_recipe_replays_detached_or_says_why_not() {
        let tmp = crate::dev::testutil::scratch("replay");
        let t = Target {
            name: "app".into(),
            dir: tmp.0.clone(),
            kind: Kind::Run,
            service: None,
        };
        let write = |args: &[&str]| {
            crate::names::Recipe {
                args: args.iter().map(OsString::from).collect(),
                cwd: tmp.0.clone(),
                project_dir: tmp.0.clone(),
            }
            .write(&tmp.0)
            .unwrap()
        };
        assert!(format!("{:#}", replay(&t).unwrap_err()).contains("no run.json"));
        write(&[
            "--config", "run", "run", "alpine", "--", "sh", "-c", "--name",
        ]);
        // Its config, relative to its working directory, is checked as the replay reads it.
        let err = format!("{:#}", replay(&t).unwrap_err());
        assert!(err.contains("config run is gone"), "{err}");
        std::fs::write(tmp.0.join("run"), b"").unwrap();
        let (args, cwd) = replay(&t).unwrap();
        assert_eq!(cwd, tmp.0);
        assert_eq!(args.last().unwrap(), "--name");
        for (flag, said) in [("-t", "-t"), ("--tty", "-t"), ("--shell", "--shell")] {
            write(&["run", flag, "--password", "s3cret", "alpine", "--", "sh"]);
            let err = format!("{:#}", replay(&t).unwrap_err());
            assert!(err.contains(&format!("run with {said}")), "{err}");
            assert!(!err.contains("s3cret"), "{err}");
            assert!(startable(&t, &[Step::Replay]).is_err());
        }
        write(&["list"]);
        assert!(replay(&t).is_err());
        // One whose working directory is gone would fail once started: refused before.
        crate::names::Recipe {
            args: ["run", "alpine"].map(OsString::from).to_vec(),
            cwd: tmp.0.join("gone"),
            project_dir: tmp.0.clone(),
        }
        .write(&tmp.0)
        .unwrap();
        let err = format!("{:#}", replay(&t).unwrap_err());
        assert!(
            err.contains("working directory") && err.contains("gone"),
            "{err}"
        );
    }

    /// A dev environment starts only while its workspace and the config it recorded are there.
    #[test]
    fn a_dev_environment_needs_its_workspace_and_recorded_config() {
        let tmp = crate::dev::testutil::scratch("dev-selection");
        let config = tmp.0.join("shop.toml");
        let identity = |config: &Path| crate::dev::Identity {
            digest: "d".into(),
            booted_secs: 0,
            created_by: String::new(),
            generation: String::new(),
            manifest: serde_json::json!({ "workspace": tmp.0, "config": config }),
            storage_backings: None,
            readied_by_its_boot: true,
        };
        std::fs::write(
            tmp.0.join("dev.json"),
            serde_json::to_vec(&identity(&config)).unwrap(),
        )
        .unwrap();
        let err = format!("{:#}", dev_selection(&tmp.0).unwrap_err());
        assert!(err.contains("config") && err.contains("gone"), "{err}");
        std::fs::write(&config, b"").unwrap();
        assert!(dev_selection(&tmp.0).is_ok());
    }

    /// What a state dir's VM recorded says what it is, wherever it sits: a run whose
    /// `--state-dir` is in the dev base is a run.
    #[test]
    fn a_state_dir_is_what_its_vm_recorded() {
        let homes = crate::dev::testutil::Homes::new("kind");
        let dir = crate::dev::plan::dev_state_base().unwrap().join("scratch");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(kind_of(&dir).unwrap(), Kind::Dev);
        let project = homes.dir().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        crate::names::Recipe {
            args: ["run", "alpine"].map(OsString::from).to_vec(),
            cwd: project.clone(),
            project_dir: project.clone(),
        }
        .write(&dir)
        .unwrap();
        assert_eq!(kind_of(&dir).unwrap(), Kind::Run);
        // `vk list` says the same, and shows the recipe's project.
        homes.name(&dir, "scratch");
        let runs = vms::list_report(vms::ListOpts {
            fields: vec!["name".into(), "project".into()],
            filter: crate::vmlist::Filter {
                kind: Some(Kind::Run),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        assert_eq!(runs, format!("scratch\t{}\n", project.display()));
        let elsewhere = homes.dir().join("env");
        std::fs::create_dir_all(&elsewhere).unwrap();
        assert_eq!(kind_of(&elsewhere).unwrap(), Kind::Run);
        std::fs::write(elsewhere.join("dev.json"), b"{}").unwrap();
        assert_eq!(kind_of(&elsewhere).unwrap(), Kind::Dev);
    }

    const O: Opts = Opts {
        config: None,
        timeout: 5,
    };

    /// A stopped run named `name`, in a state dir under the run base, whose last
    /// registration declared `services`.
    fn stopped_run(homes: &crate::dev::testutil::Homes, name: &str, services: &[&str]) -> PathBuf {
        let dir = crate::names::run_base()
            .unwrap()
            .join(format!("{name}-00000000"));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = vms::canonical(&dir);
        std::fs::write(
            dir.join(vms::LAST),
            serde_json::to_vec(&entry(&dir, 1, services)).unwrap(),
        )
        .unwrap();
        homes.name(&dir, name);
        dir
    }

    /// A registration of the VM on `dir`, managed by `pid`.
    fn entry(dir: &Path, pid: u32, services: &[&str]) -> VmEntry {
        let services: Vec<_> = services
            .iter()
            .map(|s| serde_json::json!({ "name": s, "exec_addr": "unused" }))
            .collect();
        serde_json::from_value(serde_json::json!({
            "state_dir": dir,
            "pid": pid,
            "label": "app",
            "exec_addr": "unused",
            "created_secs": 7,
            "services": services,
        }))
        .unwrap()
    }

    fn os(s: &str) -> OsString {
        s.into()
    }

    /// Restart keeps the target after its pid disappears and skips the stop if the VM is down.
    /// The test executable fails as `vk`, so its exit status identifies an attempted start.
    /// Invalid boot inputs must leave the running VM alive.
    #[test]
    fn restart_resolves_once_and_stops_only_what_can_start_again() {
        let homes = crate::dev::testutil::Homes::new("restart");
        let dir = stopped_run(&homes, "app", &[]);
        let recipe = |args: &[&str]| {
            crate::names::Recipe {
                args: args.iter().map(OsString::from).collect(),
                cwd: homes.dir().to_path_buf(),
                project_dir: homes.dir().to_path_buf(),
            }
            .write(&dir)
            .unwrap()
        };
        recipe(&["run", "alpine"]);
        let stand_in = crate::dev::testutil::StandIn::locking(&dir, false);
        let _registered = vms::register(entry(&dir, stand_in.id(), &[]));
        let t = resolve(&os(&stand_in.id().to_string())).unwrap();
        assert_eq!((t.name.as_str(), t.dir.as_path()), ("app", dir.as_path()));
        for _ in 0..2 {
            let err = format!("{:#}", restart_one(&t, O).unwrap_err());
            assert!(err.starts_with("starting app: vk exit status"), "{err}");
            assert!(running_on(&dir).is_none());
        }
        for (args, said) in [
            (&["run", "-t", "alpine"][..], "run with -t"),
            (
                &["--config", "gone.toml", "run", "alpine"][..],
                "config gone.toml is gone",
            ),
        ] {
            recipe(args);
            let mut stand_in = crate::dev::testutil::StandIn::locking(&dir, false);
            let _registered = vms::register(entry(&dir, stand_in.id(), &[]));
            let err = format!("{:#}", restart_one(&t, O).unwrap_err());
            assert!(err.contains(said), "{err}");
            assert!(stand_in.alive() && running_on(&dir).is_some());
        }
    }
}
