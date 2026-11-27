//! Lifecycle commands for VMs in `vk list`. Start and restart use the recorded dev
//! workspace and config or a run's saved recipe (`run.json`). Dev service commands use
//! `vk dev`. Run service commands go to the primary's service manager. Reset and rename
//! act on host state.
//!
//! [`plan`] and [`plan_delete`] describe start, stop and delete without changing state.
//! [`execute`] and [`remove`] carry out those steps.

use std::ffi::{OsStr, OsString};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::vmlist::Kind;
use crate::vms::{self, Ref, Selector, VmEntry};
use vk_fs::LockFile;

/// What a verb's caller says beside its REFs.
#[derive(Debug, Clone, Copy)]
pub struct Opts<'a> {
    /// the global `--config`, passed on to the `vk dev` a dev environment goes through
    pub config: Option<&'a Path>,
    /// seconds to wait for VM shutdown or for each socket operation during a service stop
    pub timeout: u64,
    /// a start builds what is not built yet, as `vk dev up` does, instead of failing
    pub build: bool,
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

/// Which VM a directory REF means when several VMs are of that project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Among {
    /// refuse, and name them: for a verb that removes something
    One,
    /// the project's own VM, its `dev` environment, when there is exactly one: what
    /// `vk dev start` in that directory would start
    ProjectVm,
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

/// A directory REF selects at most one VM. [`Among::ProjectVm`] breaks a tie with the
/// project's unique `dev` environment. Otherwise an ambiguity lists the candidates.
fn pick_one(mut found: Vec<Candidate>, among: Among, what: &str) -> Result<Option<Candidate>> {
    if found.len() <= 1 {
        return Ok(found.pop());
    }
    if among == Among::ProjectVm {
        let mut devs = found
            .iter()
            .filter(|c| c.kind == Kind::Dev && c.environment.as_deref().unwrap_or("dev") == "dev");
        if let (Some(dev), None) = (devs.next(), devs.next()) {
            return Ok(Some(dev.clone()));
        }
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
pub fn resolve(arg: &OsStr, among: Among) -> Result<Target> {
    let (sel, service) = Selector::from_ref(Ref::parse(arg)?, false)?;
    // A service is reached only through its running VM, so `PID/SERVICE` needs no name.
    let unnamed = service.is_some();
    resolve_selected(sel, service, among, unnamed)
}

/// [`resolve`] for a REF already read. `unnamed` takes a running VM without a name by its
/// pid, for what acts on it only while it runs: it is not known once it stops.
pub fn resolve_selected(
    sel: Selector,
    service: Option<String>,
    among: Among,
    unnamed: bool,
) -> Result<Target> {
    resolve_running(sel, service, among, unnamed).map(|(t, _)| t)
}

/// [`resolve_selected`], with the record of the running VM it went by, if it went by one.
fn resolve_running(
    sel: Selector,
    service: Option<String>,
    among: Among,
    unnamed: bool,
) -> Result<(Target, Option<VmEntry>)> {
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
            pick_one(named_at(&idx, &dir)?, among, &dir.display().to_string())?
        }
        Selector::Here { .. } => {
            let dir = vms::canonical(Path::new("."));
            pick_one(named_at(&idx, &dir)?, among, &dir.display().to_string())?
        }
        Selector::Pid(_) => None,
    };
    let (name, dir, kind, found) = match known {
        Some(c) => (c.name, c.dir, c.kind, None),
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
            (name, entry.state_dir.clone(), kind, Some(entry))
        }
    };
    let t = Target {
        name,
        dir,
        kind,
        service,
    };
    Ok((t, found))
}

/// Find the running VM without changing state, including during a delete preview.
fn running_on(dir: &Path) -> Option<VmEntry> {
    let dir = vms::canonical(dir);
    vms::registered().0.into_iter().find(|e| e.state_dir == dir)
}

/// Clear stale transient and registry records for `dir`. The name index is separate.
fn repair(dir: &Path) {
    // Readers skip stale records, and a later run can replace them if cleanup fails.
    let _ = crate::vmstate::clear_if_stale(dir);
    vms::forget_if_gone(dir);
}

/// The pid in the current startup record, if any.
fn starting_run(dir: &Path) -> Option<u32> {
    crate::vmstate::read(dir)
        .filter(|now| now.state == crate::vmstate::State::Starting)
        .map(|now| now.pid)
}

/// Reject the operation until the starting primary registers.
fn not_starting(t: &Target, primary_up: bool, what: &str) -> Result<()> {
    match starting_run(&t.dir).filter(|_| !primary_up) {
        Some(pid) => bail!(
            "{} is starting (pid {pid}): {what} {} once it is up",
            t.name,
            t.shown()
        ),
        None => Ok(()),
    }
}

/// One step of a start or a stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `vk dev --workspace W --environment E start` (`up` with `--build`)
    DevUp,
    /// `vk dev … start --service S` (`service up S` with `--build`), or `vk dev … service down S`
    DevService { up: bool },
    /// replay `run.json` (with `--require-cached` unless `--build`)
    Replay,
    /// a `StartCached`, `Start` or `Stop` request to the run's service manager
    Control { up: bool },
    /// stop the VM on the target's state dir — that one alone — and what it publishes
    StopVm,
    /// say so and do nothing
    Nothing(String),
}

/// What `vk delete` removes of a target, once it is down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// a dev environment's state dir
    DevDir,
    /// a run's state dir `vk` made for it
    RunDir,
    /// keep the directory and remove its name, recipe and last registration
    Forget,
    /// a service's `svc-<name>/`
    Service,
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

/// Plan removal and any forced stop. A service requires a stopped primary even with
/// `--force`. Removal holds the primary's lock so it cannot restart meanwhile.
pub fn plan_delete(
    t: &Target,
    primary_up: bool,
    force: bool,
    made: bool,
) -> Result<(Vec<Step>, Removal)> {
    let shown = t.shown();
    if t.service.is_some() {
        if primary_up {
            bail!(
                "{shown} is a service of {}, which is running: a service's state is deleted \
                 with its VM down (`vk stop {}` first)",
                t.name,
                t.name
            );
        }
        return Ok((Vec::new(), Removal::Service));
    }
    let stop = match (primary_up, force) {
        (false, _) => Vec::new(),
        (true, true) => vec![Step::StopVm],
        (true, false) => bail!("{shown} is running — `vk stop {shown}` first, or `vk delete -f`"),
    };
    let removal = match (made, t.kind) {
        (true, Kind::Dev) => Removal::DevDir,
        (true, _) => Removal::RunDir,
        (false, _) => Removal::Forget,
    };
    Ok((stop, removal))
}

/// A dev directory must be directly under the dev base and pass [`crate::dev::list::owned`]. A run directory
/// must be directly under the run base and contain a regular [`crate::names::MADE`] file.
/// Other directories may contain user files.
fn made(t: &Target) -> bool {
    let (base, owned) = match t.kind {
        Kind::Dev => (
            crate::dev::plan::dev_state_base(),
            crate::dev::list::owned(&t.dir).is_ok(),
        ),
        _ => (
            crate::names::run_base(),
            std::fs::symlink_metadata(t.dir.join(crate::names::MADE)).is_ok_and(|m| m.is_file()),
        ),
    };
    let parent = vms::canonical(&t.dir).parent().map(Path::to_path_buf);
    let base = base.ok().map(|b| vms::canonical(&b));
    parent.is_some() && parent == base && owned
}

/// Whether `path` exists; an error, not `false`, when that cannot be told.
fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("inspecting {}", path.display())),
    }
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

/// Make a replayed `vk run` follow the start's build policy rather than the recipe's: with
/// `build`, no `--require-cached`; without, exactly one. Both before the guest command's `--`.
fn build_policy(args: &mut Vec<OsString>, build: bool) {
    let at = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let mut options: Vec<OsString> = args
        .drain(..at)
        .filter(|a| a != "--require-cached")
        .collect();
    if !build {
        options.push("--require-cached".into());
    }
    options.append(args);
    *args = options;
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
/// that `what` did not happen. A `cached` start that exits 3 found something not built.
fn vk(
    what: &str,
    args: &[OsString],
    cwd: Option<&Path>,
    from_recipe: bool,
    cached: bool,
) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the running vk")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    if from_recipe {
        cmd.env(crate::FROM_RECIPE_ENV, "1");
    }
    succeeds(cmd, what, cached)
}

/// Report the child status and operation. The child inherits stderr, and its arguments
/// may contain `--password`. A `cached` start's exit 3 is a [`crate::build::NotBuilt`], so
/// it keeps that status here.
fn succeeds(mut cmd: std::process::Command, what: &str, cached: bool) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("{what}: running vk"))?;
    match status.code() {
        Some(0) => Ok(()),
        Some(3) if cached => Err(crate::build::NotBuilt(format!("{what}: vk {status}")).into()),
        _ => bail!("{what}: vk {status}"),
    }
}

/// Return the service manager's reply, or its error with the service name. A `cached`
/// start boots only an image already built: one that is not fails with a
/// [`crate::build::NotBuilt`]. For stops, `timeout` bounds each connect, read and write in seconds.
fn control_unit(
    ctl: &Path,
    shown: &str,
    unit: &str,
    up: bool,
    cached: bool,
    timeout: u64,
) -> Result<String> {
    use vk_core::fleetctl::Request;
    let unit = unit.to_string();
    let req = match (up, cached) {
        (true, false) => Request::Start { unit },
        (true, true) => Request::StartCached { unit },
        (false, _) => Request::Stop { unit },
    };
    let timeout = (!up).then(|| Duration::from_secs(timeout));
    ask(
        vms::Control::open(ctl, vms::Deadline::NEVER, timeout, None),
        shown,
        &req,
    )
}

/// Send `req` over `conn` to a service manager: [`control_unit`]'s reply, or its error.
fn ask(
    conn: Result<vms::Control>,
    shown: &str,
    req: &vk_core::fleetctl::Request,
) -> Result<String> {
    let reply = conn
        .and_then(|c| c.request(req, |line| eprintln!("{line}")))
        .with_context(|| format!("{shown}: asking its VM's service manager"))?;
    if reply.not_built {
        return Err(crate::build::NotBuilt(format!("{shown}: {}", reply.message)).into());
    }
    if !reply.ok {
        bail!("{shown}: {}", reply.message);
    }
    Ok(reply.message)
}

/// Carry out `steps` on `t`. A start boots only what is already built, unless `o.build`.
fn execute(t: &Target, steps: &[Step], o: Opts) -> Result<String> {
    let start = if o.build { "up" } else { "start" };
    let mut out = String::new();
    for step in steps {
        match step {
            Step::Nothing(what) => out.push_str(&format!("{what}\n")),
            Step::DevUp => {
                let mut args =
                    dev_args(&t.dir, o).with_context(|| format!("cannot start {}", t.name))?;
                args.push(start.into());
                vk(
                    &format!("starting {}", t.name),
                    &args,
                    None,
                    false,
                    !o.build,
                )?;
            }
            Step::DevService { up } => {
                let mut args = dev_args(&t.dir, o)?;
                let service = t.service.clone().unwrap_or_default();
                match (*up, o.build) {
                    (true, false) => {
                        args.extend(["start".into(), "--service".into(), service.into()])
                    }
                    (true, true) => args.extend(["service".into(), "up".into(), service.into()]),
                    (false, _) => {
                        args.extend(["service".into(), "down".into(), service.into()]);
                        args.extend(["--timeout".into(), o.timeout.to_string().into()]);
                    }
                }
                let what = if *up { "starting" } else { "stopping" };
                let cached = *up && !o.build;
                vk(&format!("{what} {}", t.shown()), &args, None, false, cached)?;
            }
            Step::Replay => {
                let (mut args, cwd) = replay(t)?;
                build_policy(&mut args, o.build);
                vk(
                    &format!("starting {}", t.name),
                    &args,
                    Some(&cwd),
                    true,
                    !o.build,
                )?;
            }
            Step::Control { up } => {
                let entry =
                    running_on(&t.dir).with_context(|| format!("{} is not running", t.name))?;
                let ctl = vms::control_socket(&entry)
                    .with_context(|| format!("{} runs no compose services", t.name))?;
                let unit = t.service.clone().unwrap_or_default();
                let said = control_unit(&ctl, &t.shown(), &unit, *up, !o.build, o.timeout)?;
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

/// `vk start` on each REF in turn; the exit status is [`worst`] of theirs.
pub fn start(refs: &[OsString], o: Opts) -> ExitCode {
    let mut codes = Vec::new();
    for r in refs {
        codes.push(outcome(start_one(r, o), "start", r));
    }
    worst(codes)
}

fn start_one(r: &OsStr, o: Opts) -> Result<String> {
    // A project directory means its own VM: one REF starts one VM at most.
    let t = resolve(r, Among::ProjectVm)?;
    repair(&t.dir);
    let up = running_on(&t.dir).is_some();
    // A repeated primary start succeeds. Reject service starts until registration.
    if t.service.is_none() && !up && starting_run(&t.dir).is_some() {
        return Ok(format!("{} is starting\n", t.name));
    }
    not_starting(&t, up, "start")?;
    let steps = plan(Verb::Start, &t, up)?;
    execute(&t, &steps, o)
}

/// A compose service `vk stop` stops through its VM's service manager, and the run of that
/// VM it was selected on: its record, and the run itself, held.
struct ServiceStop {
    t: Target,
    entry: VmEntry,
    run: vms::Held,
}

/// What one REF given to `vk stop` comes to.
enum Stopping {
    Service(Box<ServiceStop>),
    /// running VMs, stopped together with every other REF's
    Vms(Vec<VmEntry>),
}

/// Resolve one REF of `vk stop`, already read. A name or a service goes through its kind,
/// a running VM without a name by its pid; one that is not running is an error. A pid or a
/// directory takes every running VM it matches, and none is an error. A dev environment
/// already down is added to `stale`, for what it published to be cleared.
fn stopping(
    sel: Selector,
    service: Option<String>,
    how: vms::StopHow,
    stale: &mut Vec<PathBuf>,
) -> Result<Stopping> {
    if !matches!(sel, Selector::Named { .. }) && service.is_none() {
        let (matched, none) = vms::running_selected(sel)?;
        if matched.is_empty() {
            bail!("{}", none.trim_end());
        }
        return Ok(Stopping::Vms(matched));
    }
    let (t, found) = resolve_running(sel, service, Among::ProjectVm, true)?;
    if how != vms::StopHow::Graceful && t.service.is_some() {
        bail!(
            "{} is a compose service, stopped by its VM's service manager: --force and --kill \
             act on a VM's own run (`vk stop --force {}`)",
            t.shown(),
            t.name
        );
    }
    repair(&t.dir);
    let entry = found.or_else(|| running_on(&t.dir));
    not_starting(&t, entry.is_some(), "stop")?;
    if entry.is_none() && t.kind == Kind::Dev && t.service.is_none() {
        // What an environment published can outlive it on record: cleared, as
        // `vk dev stop` does for one already down.
        stale.push(t.dir.clone());
    }
    plan(Verb::Stop, &t, entry.is_some())?;
    match (&t.service, entry) {
        (Some(_), Some(entry)) => match vms::held_run(&entry) {
            Ok(Some(run)) => Ok(Stopping::Service(Box::new(ServiceStop { t, entry, run }))),
            Ok(None) => bail!("{} is not running: its VM {} is down", t.shown(), t.name),
            Err(why) => bail!(
                "{}: not stopped: its VM {} (pid {}): {why}",
                t.shown(),
                t.name,
                entry.pid
            ),
        },
        // That VM alone: a directory selector would also take one whose project this
        // state dir is.
        (None, Some(entry)) if vms::held_by_another(&entry) => {
            bail!("{} is held by another run", t.name)
        }
        (None, Some(entry)) => Ok(Stopping::Vms(vec![entry])),
        (_, None) => bail!("{} is not running", t.shown()),
    }
}

/// Stop the compose service `s` stands for, only on the run it was selected on and within
/// `deadline`. A run's manager is asked over a connection that run is checked to serve; a
/// dev environment's `vk dev service down` is told which run that is.
fn stop_service(s: &ServiceStop, config: Option<&Path>, deadline: vms::Deadline) -> Result<String> {
    let shown = s.t.shown();
    if deadline.passed() {
        bail!("{shown}: not stopped: the time ran out first");
    }
    let unit = s.t.service.clone().unwrap_or_default();
    if s.t.kind != Kind::Dev {
        let ctl = vms::control_socket(&s.entry)
            .with_context(|| format!("{} runs no compose services", s.t.name))?;
        let conn = vms::Control::open(&ctl, deadline, None, Some(&s.run));
        let said = ask(conn, &shown, &vk_core::fleetctl::Request::Stop { unit })?;
        return Ok(format!("{said}\n"));
    }
    let o = Opts {
        config,
        timeout: 0,
        build: false,
    };
    let mut args = dev_args(&s.t.dir, o)?;
    // Each of its socket operations bounded by what is left, rounded up to whole seconds: it
    // is held to the deadline itself here. 0 is no bound.
    let secs = deadline.left().map_or(0, |left| {
        let part = u64::from(left.subsec_nanos() > 0);
        left.as_secs().saturating_add(part).max(1)
    });
    args.extend(["service".into(), "down".into(), unit.into()]);
    args.extend(["--timeout".into(), secs.to_string().into()]);
    let exe = std::env::current_exe().context("resolving the running vk")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args).env(vms::STOP_RUN_ENV, vms::run_id(&s.entry));
    succeeds_by(cmd, &format!("stopping {shown}"), deadline)?;
    Ok(String::new())
}

/// [`succeeds`] for a child not waited for past `deadline`: one still running then is left
/// to finish, and fails the operation.
fn succeeds_by(mut cmd: std::process::Command, what: &str, deadline: vms::Deadline) -> Result<()> {
    let mut child = cmd.spawn().with_context(|| format!("{what}: running vk"))?;
    let status = loop {
        let waited = match deadline.left() {
            None => child.wait().map(Some),
            Some(_) => child.try_wait(),
        };
        match waited.with_context(|| format!("{what}: waiting for vk"))? {
            Some(status) => break status,
            None if deadline.passed() => bail!("{what}: not done when the time ran out"),
            None => std::thread::sleep(deadline.cap(Duration::from_millis(100))),
        }
    };
    if !status.success() {
        bail!("{what}: vk {status}");
    }
    Ok(())
}

/// `vk stop REF…`, each REF already read. Every REF is resolved first. Every VM is then told
/// to stop, compose services stop through their managers one after the other, and only
/// then is any VM waited for. A service whose VM is stopped too goes down with it.
/// One deadline covers all targets. Exit 1 if a REF selects nothing running or a stop fails
/// to confirm shutdown.
pub fn stop(
    refs: Vec<(Selector, Option<String>)>,
    config: Option<&Path>,
    deadline: vms::Deadline,
    how: vms::StopHow,
) -> ExitCode {
    let mut ok = true;
    let mut entries: Vec<VmEntry> = Vec::new();
    let mut services = Vec::new();
    let mut stale = Vec::new();
    for (sel, service) in refs {
        match stopping(sel, service, how, &mut stale) {
            Ok(Stopping::Service(s)) => services.push(s),
            Ok(Stopping::Vms(found)) => {
                for e in found {
                    if !entries.iter().any(|known| known.state_dir == e.state_dir) {
                        entries.push(e);
                    }
                }
            }
            Err(e) => {
                eprintln!("vk: {e:#}");
                ok = false;
            }
        }
    }
    services.retain(|s| !entries.iter().any(|e| e.state_dir == s.entry.state_dir));
    // VMs first: a service slow to stop holds none of them back.
    let vms = vms::Stops::begin(entries, stale, deadline, how);
    for s in &services {
        ok &= report(stop_service(s, config, deadline));
    }
    let (out, down) = vms.finish();
    ok &= report(Ok(out)) && down;
    exit(ok)
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

/// Report one target's outcome. On a cache miss, print the build command and return 3.
/// Other failures return 1.
fn outcome(result: Result<String>, verb: &str, r: &OsString) -> u8 {
    match result {
        Err(e) if crate::build::not_cached(&e) => {
            eprintln!("vk: {e:#}");
            eprintln!(
                "vk: hint: `vk {verb} --build {}` builds what is missing",
                r.to_string_lossy()
            );
            3
        }
        result => u8::from(!report(result)),
    }
}

/// Return 0 if all targets succeeded, 3 if only cache misses failed, or 1 for any other failure.
pub(crate) fn worst(codes: impl IntoIterator<Item = u8>) -> ExitCode {
    let code = codes
        .into_iter()
        .fold(0, |worst, code| match (worst, code) {
            (worst, 0) => worst,
            (0 | 3, 3) => 3,
            _ => 1,
        });
    ExitCode::from(code)
}

/// The exit status for whether everything went through.
fn exit(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Restart each REF in order. Continue after failures; the exit status is [`worst`] of theirs.
pub fn restart(refs: &[OsString], o: Opts) -> ExitCode {
    let mut codes = Vec::new();
    for r in refs {
        let result = resolve(r, Among::ProjectVm).and_then(|t| restart_one(&t, o));
        codes.push(outcome(result, "restart", r));
    }
    worst(codes)
}

/// Keep the resolved target across the stop. Check the primary's boot inputs before
/// stopping it, and skip the stop when the primary is down.
fn restart_one(t: &Target, o: Opts) -> Result<String> {
    repair(&t.dir);
    let up = running_on(&t.dir).is_some();
    not_starting(t, up, "restart")?;
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

/// Whether `vk delete` goes ahead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// `--dry-run`: say what would go, remove nothing
    DryRun,
    /// ask on the terminal first
    Ask,
    /// `--yes` or `--force`: remove without asking
    Go,
    /// no terminal to ask on, and neither `--yes` nor `--force`
    Refuse,
}

/// How `vk delete` proceeds, given its flags and whether a terminal can answer.
pub fn gate(yes: bool, force: bool, dry_run: bool, on_terminal: bool) -> Gate {
    match (dry_run, yes || force, on_terminal) {
        (true, _, _) => Gate::DryRun,
        (false, true, _) => Gate::Go,
        (false, false, true) => Gate::Ask,
        (false, false, false) => Gate::Refuse,
    }
}

impl Step {
    /// What this step would do to `t`, as `vk delete` lists it before it acts.
    pub fn describe(&self, t: &Target) -> String {
        let name = t.shown();
        match self {
            Step::Nothing(what) => what.clone(),
            Step::StopVm | Step::Control { up: false } | Step::DevService { up: false } => {
                format!("stop {name}")
            }
            Step::DevUp
            | Step::Replay
            | Step::Control { up: true }
            | Step::DevService { up: true } => format!("start {name}"),
        }
    }
}

impl Removal {
    /// What this removal would do to `t`, as `vk delete` lists it before it acts.
    pub fn describe(self, t: &Target) -> String {
        let name = t.shown();
        let dir = t.dir.display();
        match self {
            Removal::DevDir => format!(
                "delete dev environment {name}{}: its state dir {dir}, storage and all",
                with_services(&t.dir)
            ),
            Removal::RunDir => format!(
                "delete {name}{}: its state dir {dir}",
                with_services(&t.dir)
            ),
            Removal::Forget => format!(
                "forget {name}: its name, {} and {} go; its state dir {dir}, not known to be \
                 one vk made, stays",
                crate::names::RECIPE,
                vms::LAST
            ),
            Removal::Service => format!(
                "delete {name}: what it keeps in {}",
                t.dir.join(service_dir(t)).display()
            ),
        }
    }
}

/// List service directories with a console log for the deletion preview. Omit the suffix
/// when no service matches.
fn with_services(dir: &Path) -> String {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        // A run makes a directory for every declared service; one that booted left a console.
        .filter(|e| e.path().join(crate::run::CONSOLE_LOG).exists())
        .filter_map(|e| Some(e.file_name().to_str()?.strip_prefix("svc-")?.to_string()))
        .collect();
    names.sort();
    match names.len() {
        0 => String::new(),
        1 => format!(" and its service {}", names[0]),
        _ => format!(" and its services {}", names.join(", ")),
    }
}

/// Keep the planned state directory open so a replacement cannot reuse its inode. Targets
/// in one directory share its descriptor and lock. `None` records a missing directory.
struct Planned {
    t: Target,
    stop: Vec<Step>,
    removal: Removal,
    /// Unlocked as it drops: a run started next must find the dir free at once.
    dir: Option<Rc<LockFile>>,
    /// the service directory opened during planning, if present
    svc: Option<LockFile>,
}

impl Planned {
    /// Whether `self` and `other` were planned on the same state dir.
    fn same_dir(&self, other: &Planned) -> bool {
        let id = |f: &std::fs::File| f.metadata().ok().map(|m| (m.dev(), m.ino()));
        match (&self.dir, &other.dir) {
            (Some(a), Some(b)) => id(a).is_some() && id(a) == id(b),
            (None, None) => self.t.dir == other.t.dir,
            _ => false,
        }
    }
}

/// Resolve the REF `r` for `vk delete` and plan it.
fn plan_one(r: &OsStr, force: bool) -> Result<Planned> {
    let t = resolve(r, Among::One)?;
    let dir = match std::fs::File::open(&t.dir) {
        Ok(f) => Some(Rc::new(LockFile::new(f))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("opening {}", t.dir.display())),
    };
    let up = running_on(&t.dir).is_some();
    not_starting(&t, up, "delete")?;
    let (stop, removal) = plan_delete(&t, up, force, made(&t))?;
    let mut svc = None;
    if removal == Removal::Service {
        declared(&t)?;
        if let Some(dir) = &dir {
            svc = open_service(&t, dir)?.map(LockFile::new);
        }
    }
    Ok(Planned {
        t,
        stop,
        removal,
        dir,
        svc,
    })
}

/// Open `t`'s service's `svc-<name>/` in its state dir, open as `dir`, never following a
/// link, so its lock can be taken and the dir removed through it; `None` when there is none.
fn open_service(t: &Target, dir: &std::fs::File) -> Result<Option<std::fs::File>> {
    let name = service_dir(t);
    let path = t.dir.join(&name);
    let svc = match vk_fs::open_dir_in(dir.as_fd(), OsStr::new(&name)) {
        Ok(svc) => svc,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        // A link or a file among them: left alone.
        Err(e) => return Err(e).with_context(|| format!("{} left alone", path.display())),
    };
    Ok(Some(vk_fs::reopen_dir(svc.as_fd())?.into()))
}

/// `svc-<name>`: where `t`'s service keeps its state, in its VM's state dir.
fn service_dir(t: &Target) -> String {
    format!("svc-{}", t.service.as_deref().unwrap_or_default())
}

/// Only the last VM registration establishes which `svc-<name>/` entries belong to services.
fn declared(t: &Target) -> Result<()> {
    let service = t.service.as_deref().unwrap_or_default();
    let dir = t.dir.join(service_dir(t));
    match vms::last_entry(&t.dir)? {
        Some(e) if e.services.iter().any(|s| s.name == service) => Ok(()),
        Some(_) => bail!(
            "{} declared no service {service} when it last ran: {} is not its to delete",
            t.name,
            dir.display()
        ),
        None => bail!(
            "{} has no record of the services it ran: {} is not known to be {service}'s",
            t.name,
            dir.display()
        ),
    }
}

/// Lock the directory opened during planning and verify its path still names it. A run holds
/// this lock from before its pull through exit, even if it never registers. A directory
/// missing during planning must still be absent.
fn hold(p: &Planned) -> Result<Option<&LockFile>> {
    let t = &p.t;
    let Some(dir) = p.dir.as_deref() else {
        if exists(&t.dir)? {
            bail!(
                "{} was made again since {} was listed — run `vk delete` again",
                t.dir.display(),
                t.name
            );
        }
        return Ok(None);
    };
    // A second target in the same dir shares this descriptor, which already holds the lock.
    lock(dir, &t.dir, t)?;
    still_at(t, dir)?;
    if p.removal == Removal::Service {
        declared(t)?;
        // A run given it as its own `--state-dir` holds the service's dir's lock alone.
        let path = t.dir.join(service_dir(t));
        match &p.svc {
            Some(svc) => lock(svc, &path, t)?,
            None if exists(&path)? => bail!(
                "{} was made since {} was listed — run `vk delete` again",
                path.display(),
                t.shown()
            ),
            None => {}
        }
    }
    Ok(Some(dir))
}

/// Take the lock of the dir `path`, open as `dir`, for `t`'s removal: refused while a run
/// holds it.
fn lock(dir: &std::fs::File, path: &Path, t: &Target) -> Result<()> {
    match dir.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => {
            let held = crate::dev::lock_holder(path).unwrap_or_else(|| "another vk".into());
            bail!("{} is in use by {held} — stop that first", t.shown());
        }
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}

/// Verify that the state directory path still names the inode held open since planning.
fn still_at(t: &Target, dir: &std::fs::File) -> Result<()> {
    let again = "— run `vk delete` again";
    let now = match std::fs::symlink_metadata(&t.dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "{} went away since {} was listed {again}",
            t.dir.display(),
            t.name
        ),
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", t.dir.display())),
    };
    let was = dir
        .metadata()
        .with_context(|| format!("inspecting {}", t.dir.display()))?;
    if (now.dev(), now.ino()) != (was.dev(), was.ino()) {
        bail!(
            "{} is another directory since {} was listed {again}",
            t.dir.display(),
            t.name
        );
    }
    Ok(())
}

/// Apply the planned removal with the state directory lock from [`hold`].
fn remove(p: &Planned, lock: Option<&LockFile>) -> Result<String> {
    let t = &p.t;
    let idx = crate::names::Index::open()?;
    let Some(lock) = lock else {
        // A name left on a state dir something else removed: only the names still on that
        // dir go, under the index lock, while it is still gone.
        let _names = idx.lock()?;
        if exists(&t.dir)? {
            bail!(
                "{} was made again since {} was listed",
                t.dir.display(),
                t.name
            );
        }
        idx.release_locked(&t.dir)?;
        return Ok(format!("forgot {} (its state dir was gone)\n", t.name));
    };
    match p.removal {
        Removal::DevDir | Removal::RunDir => {
            crate::publish::stop_all_quietly(&t.dir, Duration::from_secs(5));
            // Its names go under the index lock, held across the removal as `vk dev gc`
            // holds it, so a run that makes the dir again meanwhile keeps the name it claims.
            let _names = idx.lock()?;
            remove_tree(&t.dir, lock)?;
            idx.release_locked(&t.dir)?;
            Ok(format!("removed {}\n", t.name))
        }
        Removal::Forget => {
            // Through the held state dir, so one put in its place meanwhile loses nothing.
            // The name goes last, so a recipe left behind is never left unnamed, and only
            // while the path still leads to that dir.
            for f in [crate::names::RECIPE, vms::LAST] {
                vk_fs::remove_file_in(lock.as_fd(), OsStr::new(f))
                    .with_context(|| format!("removing {}", t.dir.join(f).display()))?;
            }
            let _names = idx.lock()?;
            still_at(t, lock)?;
            idx.release_locked(&t.dir)?;
            Ok(format!(
                "removed {} (its state dir {} stays)\n",
                t.name,
                t.dir.display()
            ))
        }
        Removal::Service => {
            let Some(svc) = &p.svc else {
                return Ok(format!("{} holds no state\n", t.shown()));
            };
            // The dir planned on and locked, through the held state dir, only while its name
            // still leads there.
            let name = service_dir(t);
            let done = vk_fs::remove_tree_in(lock.as_fd(), OsStr::new(&name), svc.as_fd())?;
            kept(&t.dir, &done)?;
            Ok(format!("removed {}\n", t.shown()))
        }
    }
}

/// Remove the locked tree through its parent without following symlinks. [`vk_fs::remove_tree_in`]
/// checks its identity and reports entries it skips.
fn remove_tree(dir: &Path, lock: &std::fs::File) -> Result<()> {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        bail!("{} is not a directory to remove", dir.display());
    };
    let parent_fd = vk_fs::open_dir(parent)?;
    let done = vk_fs::remove_tree_in(parent_fd.as_fd(), name, lock.as_fd())?;
    kept(parent, &done)
}

/// An error naming what [`vk_fs::remove_tree_in`] left in `at`, if anything.
fn kept(at: &Path, done: &vk_fs::RemoveTree) -> Result<()> {
    if done.skipped.is_empty() {
        return Ok(());
    }
    let kept: Vec<String> = done
        .skipped
        .iter()
        .map(|p| at.join(p).display().to_string())
        .collect();
    bail!(
        "left in place, as a mount, on another device or another user's: {}",
        kept.join(", ")
    )
}

/// Plan every REF before prompting. After any forced stops, lock and check every state
/// directory before the first removal. A planning or locking failure prevents all removals.
pub fn delete(refs: &[OsString], force: bool, yes: bool, dry_run: bool, o: Opts) -> ExitCode {
    let mut planned = Vec::new();
    let mut ok = true;
    for r in refs {
        match plan_one(r, force) {
            // A target named twice is deleted once; targets in one state dir share its lock.
            Ok(p)
                if planned
                    .iter()
                    .any(|q: &Planned| q.same_dir(&p) && q.t.service == p.t.service) => {}
            Ok(mut p) => {
                if let Some(q) = planned.iter().find(|q| q.same_dir(&p)) {
                    p.dir = q.dir.clone();
                }
                planned.push(p);
            }
            Err(e) => {
                eprintln!("vk: {e:#}");
                ok = false;
            }
        }
    }
    let list: String = planned
        .iter()
        .flat_map(|p| {
            let stops = p.stop.iter().map(|s| s.describe(&p.t));
            stops.chain([p.removal.describe(&p.t)])
        })
        .map(|line| format!("  {line}\n"))
        .collect();
    let gate = gate(yes, force, dry_run, crate::dev::on_terminal());
    if gate == Gate::DryRun {
        let written = crate::write_report(&format!("would:\n{list}"));
        return if ok { written } else { exit(false) };
    }
    if !ok {
        eprintln!("vk: nothing was deleted");
        return exit(false);
    }
    match gate {
        Gate::Refuse => {
            eprint!("vk delete would:\n{list}vk: nothing was deleted: --yes deletes it\n");
            return exit(false);
        }
        Gate::Ask => {
            eprint!("vk delete will:\n{list}");
            match crate::dev::ask_on_terminal("go ahead?") {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("vk: nothing was deleted");
                    return exit(false);
                }
                Err(e) => {
                    eprintln!("vk: {e:#}");
                    return exit(false);
                }
            }
        }
        Gate::Go | Gate::DryRun => {}
    }
    for p in &planned {
        ok &= report(execute(&p.t, &p.stop, o));
        repair(&p.t.dir);
    }
    let mut held = Vec::new();
    for p in &planned {
        match hold(p) {
            Ok(lock) => held.push(lock),
            Err(e) => {
                eprintln!("vk: {e:#}");
                ok = false;
            }
        }
    }
    if !ok {
        eprintln!("vk: nothing was deleted");
        return exit(false);
    }
    for (p, lock) in planned.iter().zip(&held) {
        ok &= report(remove(p, *lock));
    }
    exit(ok)
}

/// Prune a stopped dev environment after checking ownership of its state directory.
pub fn reset(r: &OsStr, options: &crate::dev::prune::Options) -> Result<String> {
    let t = resolve(r, Among::One)?;
    if let Some(service) = &t.service {
        bail!(
            "{}/{service} is a compose service: `vk reset` takes a dev environment \
             (`vk delete {}/{service}` removes a service's state)",
            t.name,
            t.name
        );
    }
    if t.kind != Kind::Dev {
        bail!(
            "{} is a run: `vk reset` takes a dev environment \
             (`vk delete {}` removes it)",
            t.name,
            t.name
        );
    }
    crate::dev::list::owned(&t.dir).with_context(|| format!("{} is not reset", t.name))?;
    crate::dev::prune::run_in(&t.dir, options)
}

/// Resolve one VM and change its indexed name.
pub fn rename(old: &OsStr, new: &str) -> Result<String> {
    let t = resolve(old, Among::One)?;
    if let Some(service) = &t.service {
        bail!(
            "{}/{service} is a compose service: `vk rename` names a VM",
            t.name
        );
    }
    let dev_base = crate::dev::plan::dev_state_base()?;
    let was = crate::names::Index::open()?.rename(&dev_base, &t.dir, &t.name, new)?;
    Ok(format!(
        "renamed {} to {new}\n",
        was.unwrap_or(t.name.clone())
    ))
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

    #[test]
    fn delete_refuses_what_runs_unless_forced_and_never_deletes_a_users_dir() {
        use Removal::*;
        let run = target(Kind::Run, None);
        assert!(plan_delete(&run, true, false, true).is_err());
        assert_eq!(
            plan_delete(&run, true, true, true).unwrap(),
            (vec![Step::StopVm], RunDir)
        );
        assert_eq!(
            plan_delete(&run, false, false, false).unwrap(),
            (vec![], Forget)
        );
        let dev = target(Kind::Dev, None);
        assert_eq!(
            plan_delete(&dev, false, false, true).unwrap(),
            (vec![], DevDir)
        );
        assert_eq!(
            plan_delete(&dev, false, false, false).unwrap(),
            (vec![], Forget)
        );
        // A service's state goes only with its VM down, forced or not.
        let svc = target(Kind::Run, Some("db"));
        assert_eq!(
            plan_delete(&svc, false, false, true).unwrap(),
            (vec![], Service)
        );
        for force in [false, true] {
            let err = plan_delete(&svc, true, force, true).unwrap_err();
            assert!(err.to_string().contains("`vk stop app` first"), "{err}");
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

    /// A directory REF is one VM at most: the only one of that project, else — to start or
    /// stop — its `dev` environment when that settles it; several are otherwise refused.
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
        for among in [Among::One, Among::ProjectVm] {
            assert_eq!(pick_one(vec![], among, "/w").unwrap(), None);
            assert_eq!(
                pick_one(vec![tool.clone()], among, "/w").unwrap(),
                Some(tool.clone())
            );
        }
        let all = vec![test.clone(), tool.clone(), shop.clone()];
        assert_eq!(
            pick_one(all.clone(), Among::ProjectVm, "/w").unwrap(),
            Some(shop.clone())
        );
        let err = pick_one(all, Among::One, "/w").unwrap_err().to_string();
        assert!(
            err.contains("3 VMs are of /w: shop-test, tool, shop"),
            "{err}"
        );
        // No `dev` environment, or two of them: nothing settles it.
        assert!(pick_one(vec![test.clone(), tool.clone()], Among::ProjectVm, "/w").is_err());
        assert!(pick_one(vec![shop.clone(), shop], Among::ProjectVm, "/w").is_err());
    }

    /// `--dry-run` wins; `--yes` or `--force` go ahead; otherwise a terminal is asked, and
    /// without one nothing is deleted.
    #[test]
    fn delete_asks_on_a_terminal_and_refuses_without_one() {
        for term in [true, false] {
            for (y, f) in [(false, false), (true, false), (false, true), (true, true)] {
                assert_eq!(gate(y, f, true, term), Gate::DryRun);
            }
            assert_eq!(gate(true, false, false, term), Gate::Go);
            assert_eq!(gate(false, true, false, term), Gate::Go);
        }
        assert_eq!(gate(false, false, false, true), Gate::Ask);
        assert_eq!(gate(false, false, false, false), Gate::Refuse);
    }

    /// The list shown before a delete names what goes, and what stays.
    #[test]
    fn delete_steps_say_what_goes() {
        let run = target(Kind::Run, None);
        assert_eq!(Step::StopVm.describe(&run), "stop app");
        assert_eq!(
            Removal::RunDir.describe(&run),
            "delete app: its state dir /s/app"
        );
        let forget = Removal::Forget.describe(&run);
        assert!(
            forget.contains("run.json and .virtkit-last.json go"),
            "{forget}"
        );
        assert!(
            forget.contains("/s/app, not known to be one vk made, stays"),
            "{forget}"
        );
        let dev = target(Kind::Dev, None);
        assert!(
            Removal::DevDir
                .describe(&dev)
                .starts_with("delete dev environment app")
        );
        let svc = target(Kind::Run, Some("db"));
        assert_eq!(
            Removal::Service.describe(&svc),
            "delete app/db: what it keeps in /s/app/svc-db"
        );
        assert_eq!(Step::Control { up: false }.describe(&svc), "stop app/db");
    }

    /// A queued service is stopped only through the run its VM was selected on, and only
    /// before the deadline: a manager another process listens with by then, as a run that
    /// replaced it would, is never asked.
    #[test]
    fn a_queued_service_stop_goes_only_to_its_run() {
        use std::io::Read;
        let _env = crate::dev::testutil::env_guard();
        let tmp = crate::dev::testutil::scratch("stop-svc");
        let stand_in = crate::dev::testutil::StandIn::spawn();
        let vsock = tmp.0.join("vsock.sock");
        let mut entry = run_of(&tmp.0, &stand_in, &["db"]);
        entry.exec_addr = format!("vsock-auto://{}:4444", vsock.display());
        let ctl = crate::manager::host_control_socket(&vsock);
        let listener = vk_core::unixpath::bind(&ctl).unwrap();
        let s = ServiceStop {
            t: target(Kind::Run, Some("db")),
            run: vms::held_run(&entry).unwrap().unwrap(),
            entry,
        };
        let err = stop_service(&s, None, vms::Deadline::NEVER).unwrap_err();
        assert!(
            format!("{err:#}").contains("no longer served by the run selected"),
            "{err:#}"
        );
        let (mut conn, _) = listener.accept().unwrap();
        let mut asked = Vec::new();
        conn.read_to_end(&mut asked).unwrap();
        assert!(asked.is_empty(), "{asked:?}");
        let err = stop_service(&s, None, vms::Deadline::in_secs(0)).unwrap_err();
        assert!(format!("{err:#}").contains("time ran out"), "{err:#}");
    }

    /// A child still running at the deadline fails the operation rather than holding it.
    #[test]
    fn a_child_past_the_deadline_is_not_waited_for() {
        let _env = crate::dev::testutil::env_guard();
        // Left to end by itself, shortly after.
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("3");
        let began = std::time::Instant::now();
        let err = succeeds_by(cmd, "stopping app/db", vms::Deadline::in_secs(1)).unwrap_err();
        assert!(began.elapsed() < Duration::from_secs(5));
        assert!(format!("{err:#}").contains("stopping app/db"), "{err:#}");
    }

    /// A child that fails is reported by what it was for and how it ended, never by its
    /// arguments, which for a replayed run hold whatever its command line held.
    #[test]
    fn a_failed_child_never_shows_its_arguments() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "exit 3", "--password=s3cret-sentinel"]);
        let err = succeeds(cmd, "starting app", false).unwrap_err();
        assert!(!crate::build::not_cached(&err));
        let err = format!("{err:#}");
        assert!(!err.contains("s3cret-sentinel"), "{err}");
        assert!(err.contains("starting app") && err.contains('3'), "{err}");
    }

    /// A start that boots only what is built keeps its child's exit 3, and the exit status of
    /// several is 3 only when each that failed was not built.
    #[test]
    fn a_start_not_built_exits_3_through_its_child_and_its_peers() {
        let child = |code: u8| {
            let mut cmd = std::process::Command::new("sh");
            cmd.args(["-c", &format!("exit {code}")]);
            cmd
        };
        let err = succeeds(child(3), "starting app", true).unwrap_err();
        assert!(crate::build::not_cached(&err), "{err:#}");
        assert!(!crate::build::not_cached(
            &succeeds(child(1), "starting app", true).unwrap_err()
        ));
        assert_eq!(worst([]), ExitCode::SUCCESS);
        assert_eq!(worst([0, 0]), ExitCode::SUCCESS);
        assert_eq!(worst([0, 3, 3]), ExitCode::from(3));
        assert_eq!(worst([3, 1]), ExitCode::from(1));
        assert_eq!(worst([1, 3, 0]), ExitCode::from(1));
    }

    /// A manager that cannot be asked, and one that refuses a unit it does not know, are
    /// errors; what it says when it acts is what `vk` says.
    #[test]
    fn the_service_manager_answers_or_the_service_fails() {
        use std::io::{BufRead, Write};
        let t = crate::dev::testutil::scratch("control");
        let gone = t.0.join("gone.sock");
        let err = control_unit(&gone, "app/db", "db", false, false, 1).unwrap_err();
        assert!(!crate::build::not_cached(&err));
        assert!(format!("{err:#}").contains("service manager"), "{err:#}");
        let ctl = t.0.join("ctl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&ctl).unwrap();
        let serve = std::thread::spawn(move || {
            for reply in [
                vk_core::fleetctl::Reply::err("no such unit \"nope\""),
                vk_core::fleetctl::Reply::ok("db already running (10.0.2.3)"),
                vk_core::fleetctl::Reply::not_built("db is not built"),
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
        let err = control_unit(&ctl, "app/nope", "nope", false, false, 5).unwrap_err();
        assert!(err.to_string().contains("app/nope: no such unit"), "{err}");
        let said = control_unit(&ctl, "app/db", "db", true, false, 5).unwrap();
        assert_eq!(said, "db already running (10.0.2.3)");
        let err = control_unit(&ctl, "app/db", "db", true, true, 5).unwrap_err();
        assert!(crate::build::not_cached(&err), "{err:#}");
        assert!(err.to_string().contains("app/db: db is not built"), "{err}");
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
        // A recipe run cache-only replays as the start asks: `--build` builds.
        write(&[
            "run",
            "--require-cached",
            "alpine",
            "--",
            "--require-cached",
        ]);
        let (recorded, _) = replay(&t).unwrap();
        let cached = |a: &[OsString]| a.iter().filter(|a| *a == "--require-cached").count();
        let mut args = recorded.clone();
        build_policy(&mut args, true);
        assert_eq!(cached(&args), 1);
        assert_eq!(args.last().unwrap(), "--require-cached");
        let at = args.iter().position(|a| a == "--").unwrap();
        assert!(
            !args[..at].iter().any(|a| a == "--require-cached"),
            "{args:?}"
        );
        build_policy(&mut args, false);
        assert_eq!(cached(&args), 2);
        build_policy(&mut args, false);
        assert_eq!(cached(&args), 2);
        // A recipe that built replays cache-only unless `--build`.
        write(&["run", "alpine"]);
        let (mut args, _) = replay(&t).unwrap();
        build_policy(&mut args, false);
        assert_eq!(cached(&args), 1);
        build_policy(&mut args, true);
        assert_eq!(cached(&args), 0);
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

    /// Whether `vk delete -y REFS` succeeds.
    fn deleted(refs: &[OsString]) -> bool {
        delete(refs, false, true, false, O) == ExitCode::SUCCESS
    }

    const O: Opts = Opts {
        config: None,
        timeout: 5,
        build: false,
    };

    /// A stopped run named `name`, in a state dir `vk` made for it under the run base, whose
    /// last registration declared `services`.
    fn stopped_run(homes: &crate::dev::testutil::Homes, name: &str, services: &[&str]) -> PathBuf {
        let dir = crate::names::run_base()
            .unwrap()
            .join(format!("{name}-00000000"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(crate::names::MADE), b"").unwrap();
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

    /// [`entry`] of the run `stand_in` stands for, with its start time as `vk run` records it.
    fn run_of(dir: &Path, stand_in: &crate::dev::testutil::StandIn, services: &[&str]) -> VmEntry {
        let mut e = entry(dir, stand_in.id(), services);
        e.pid_start_ticks = crate::usage::proc_starttime(i32::try_from(e.pid).unwrap());
        e
    }

    fn os(s: &str) -> OsString {
        s.into()
    }

    /// A service's `svc-<name>/` goes only for a service its VM declared, and only while
    /// that VM stays down: one started between the plan and the removal keeps it.
    #[test]
    fn a_service_is_deleted_only_as_declared_and_with_its_vm_down() {
        let homes = crate::dev::testutil::Homes::new("rm-svc");
        let dir = stopped_run(&homes, "app", &["db", "link"]);
        let plain = stopped_run(&homes, "plain", &[]);
        for d in [
            dir.join("svc-db"),
            dir.join("svc-notes"),
            plain.join("svc-notes"),
        ] {
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("data"), b"keep").unwrap();
        }
        for r in ["app/notes", "plain/notes"] {
            let err = plan_one(&os(r), false).err().unwrap();
            assert!(
                format!("{err:#}").contains("declared no service notes"),
                "{err:#}"
            );
        }
        let p = plan_one(&os("app/db"), false).unwrap();
        let run = crate::dev::list::try_lock_state_dir(&dir).unwrap();
        let err = hold(&p).unwrap_err();
        assert!(format!("{err:#}").contains("in use"), "{err:#}");
        assert!(dir.join("svc-db/data").exists());
        drop(run);
        let lock = hold(&p).unwrap().unwrap();
        assert_eq!(remove(&p, Some(lock)).unwrap(), "removed app/db\n");
        assert!(!dir.join("svc-db").exists() && dir.join("svc-notes/data").exists());
        // A link where the service's directory would be is left, and what it leads to.
        std::os::unix::fs::symlink(plain.join("svc-notes"), dir.join("svc-link")).unwrap();
        let err = plan_one(&os("app/link"), false).err().unwrap();
        assert!(format!("{err:#}").contains("left alone"), "{err:#}");
        assert!(plain.join("svc-notes/data").exists());
    }

    /// A run given a service's dir as its own `--state-dir` holds that dir's lock alone:
    /// the service's state stays, and so does every other target of the same `vk delete`.
    #[test]
    fn a_service_dir_in_use_on_its_own_is_kept() {
        let homes = crate::dev::testutil::Homes::new("rm-svc-lock");
        let dir = stopped_run(&homes, "app", &["db"]);
        let other = stopped_run(&homes, "other", &[]);
        std::fs::create_dir_all(dir.join("svc-db")).unwrap();
        std::fs::write(dir.join("svc-db/data"), b"keep").unwrap();
        let run = crate::dev::list::try_lock_state_dir(&dir.join("svc-db")).unwrap();
        assert_eq!(
            delete(&[os("app/db"), os("other")], false, true, false, O),
            ExitCode::from(1)
        );
        assert!(dir.join("svc-db/data").exists() && other.exists());
        drop(run);
        assert!(deleted(&[os("app/db")]));
        assert!(!dir.join("svc-db").exists());
    }

    /// A `dev.json` that does not read as an identity is no proof that a dir is a dev
    /// environment's: deleting the run that used it, then the dir by its own name, only
    /// forgets them. One that reads, with no run's recipe beside it, goes whole.
    #[test]
    fn a_dev_dir_goes_whole_only_with_the_identity_it_recorded() {
        let homes = crate::dev::testutil::Homes::new("rm-devjson");
        let dir = crate::dev::plan::dev_state_base().unwrap().join("scratch");
        std::fs::create_dir_all(dir.join("editor")).unwrap();
        let dir = vms::canonical(&dir);
        std::fs::write(dir.join("dev.json"), b"{}").unwrap();
        std::fs::write(dir.join(crate::names::RECIPE), b"{}").unwrap();
        homes.name(&dir, "app");
        let p = plan_one(&os("app"), false).unwrap();
        assert_eq!(p.removal, Removal::Forget);
        drop(p);
        let all = [os("app"), os("scratch")];
        for r in &all {
            assert!(deleted(std::slice::from_ref(r)));
            assert!(dir.join("editor").is_dir());
        }
        assert!(!dir.join(crate::names::RECIPE).exists());
        let identity = serde_json::json!({ "digest": "d", "booted_secs": 0, "manifest": {} });
        std::fs::write(dir.join("dev.json"), identity.to_string()).unwrap();
        assert_eq!(
            plan_one(&os("scratch"), false).unwrap().removal,
            Removal::DevDir
        );
        assert!(deleted(&[os("scratch")]));
        assert!(!dir.exists());
    }

    /// A state dir `vk` made goes whole; any other only loses its name, recipe and last
    /// registration. A failure to remove either keeps the name.
    #[test]
    fn delete_removes_only_what_vk_made() {
        let homes = crate::dev::testutil::Homes::new("rm-own");
        let made = stopped_run(&homes, "made", &[]);
        let unmarked = stopped_run(&homes, "unmarked", &[]);
        std::fs::remove_file(unmarked.join(crate::names::MADE)).unwrap();
        let mine = homes.dir().join("mine");
        std::fs::create_dir_all(&mine).unwrap();
        homes.name(&mine, "mine");
        for d in [&unmarked, &mine] {
            std::fs::write(d.join(crate::names::RECIPE), b"{}").unwrap();
            std::fs::write(d.join(vms::LAST), b"{}").unwrap();
            std::fs::write(d.join("notes.txt"), b"keep").unwrap();
        }
        let run = |dir: &Path| Target {
            name: String::new(),
            dir: dir.to_path_buf(),
            kind: Kind::Run,
            service: None,
        };
        assert!(super::made(&run(&made)));
        assert!(!super::made(&run(&unmarked)) && !super::made(&run(&mine)));
        let refs = [os("made"), os("unmarked"), os("mine")];
        assert!(deleted(&refs));
        let idx = crate::names::Index::open().unwrap();
        assert!(!made.exists());
        for d in [&unmarked, &mine] {
            assert!(d.join("notes.txt").exists());
            assert!(!d.join(crate::names::RECIPE).exists() && !d.join(vms::LAST).exists());
            assert_eq!(idx.name_of(d), None);
        }
        // A recipe that cannot be removed leaves the name it is known by.
        std::fs::create_dir(mine.join(crate::names::RECIPE)).unwrap();
        homes.name(&mine, "mine");
        assert_eq!(
            delete(&[os("mine")], false, true, false, O),
            ExitCode::from(1)
        );
        assert_eq!(idx.lookup("mine"), Some(vms::canonical(&mine)));
    }

    /// Repeated primary starts succeed. Service start, stop, restart and delete refuse a starting VM.
    #[test]
    fn a_starting_vm_is_left_to_come_up() {
        let homes = crate::dev::testutil::Homes::new("starting");
        let dir = stopped_run(&homes, "app", &["db"]);
        // This process is the run that holds the dir and has registered nothing yet.
        let _held = crate::dev::list::try_lock_state_dir(&dir).unwrap();
        crate::vmstate::starting(&dir);
        assert_eq!(start_one(&os("app"), O).unwrap(), "app is starting\n");
        let refused = |e: anyhow::Error, what: &str| {
            let e = format!("{e:#}");
            let pid = std::process::id();
            assert!(
                e.contains(&format!("app is starting (pid {pid}): {what}")),
                "{e}"
            );
        };
        refused(start_one(&os("app/db"), O).unwrap_err(), "start app/db");
        refused(plan_one(&os("app"), false).err().unwrap(), "delete app");
        let t = resolve(&os("app"), Among::ProjectVm).unwrap();
        refused(restart_one(&t, O).unwrap_err(), "restart app");
        let sel = vms::Selector::from_ref(vms::Ref::parse(&os("app")).unwrap(), false)
            .unwrap()
            .0;
        let stop = stopping(sel, None, vms::StopHow::Graceful, &mut Vec::new());
        refused(stop.err().unwrap(), "stop app");
        assert!(dir.exists());
    }

    /// Delete previews and preflight failures preserve all records. Once confirmed, delete can
    /// prune its own registration while the state directory still exists.
    #[test]
    fn only_a_delete_that_goes_ahead_writes() {
        let homes = crate::dev::testutil::Homes::new("rm-preview");
        let app = stopped_run(&homes, "app", &[]);
        let idx = crate::names::Index::open().unwrap();
        let abandoned = crate::names::run_base().unwrap().join("boot-00000000");
        std::fs::create_dir_all(&abandoned).unwrap();
        std::fs::write(abandoned.join(crate::names::MADE), b"").unwrap();
        assert!(idx.provisional().claim_exact(&abandoned, "boot").unwrap());
        let reg = vms::registry_dir().unwrap();
        std::fs::create_dir_all(&reg).unwrap();
        let mut dead = entry(&app, std::process::id(), &[]);
        dead.pid_start_ticks = Some(1);
        let slug = reg.join(format!("{}.json", vms::slug(&app)));
        std::fs::write(&slug, serde_json::to_vec(&dead).unwrap()).unwrap();
        let untouched = || {
            assert!(abandoned.exists() && idx.lookup("boot").is_some());
            assert!(app.exists() && slug.exists());
        };
        assert_eq!(
            delete(&[os("app")], false, true, true, O),
            ExitCode::SUCCESS
        );
        untouched();
        assert_eq!(
            delete(&[os("app"), os("nope")], false, true, false, O),
            ExitCode::from(1)
        );
        untouched();
        assert!(deleted(&[os("app")]));
        assert!(!app.exists() && !slug.exists());
        assert!(abandoned.exists());
    }

    /// Stopping a VM or selecting an empty project preserves other VMs' registrations and names.
    #[test]
    fn a_stop_repairs_only_its_own_vm() {
        let homes = crate::dev::testutil::Homes::new("stop-local");
        let app = stopped_run(&homes, "app", &[]);
        let legacy = crate::dev::plan::dev_state_base().unwrap().join("old-1111");
        std::fs::create_dir_all(&legacy).unwrap();
        let identity = serde_json::json!({
            "digest": "d", "booted_secs": 1,
            "manifest": {"workspace": "/a/old", "environment": "dev"},
        });
        std::fs::write(legacy.join("dev.json"), identity.to_string()).unwrap();
        let legacy = vms::canonical(&legacy);
        let gone = stopped_run(&homes, "gone", &[]);
        let reg = vms::registry_dir().unwrap();
        std::fs::create_dir_all(&reg).unwrap();
        let mut dead = entry(&gone, std::process::id(), &[]);
        dead.pid_start_ticks = Some(1);
        let slug = reg.join(format!("{}.json", vms::slug(&gone)));
        std::fs::write(&slug, serde_json::to_vec(&dead).unwrap()).unwrap();
        let idx = crate::names::Index::open().unwrap();
        let untouched = || {
            assert_eq!(idx.name_of(&legacy), None);
            assert!(slug.exists(), "another run's entry was dropped");
        };

        let mut stand_in = crate::dev::testutil::StandIn::locking(&app, false);
        let _registered = vms::register(run_of(&app, &stand_in, &[]));
        let sel = Selector::parse(&os("app")).unwrap();
        let deadline = vms::Deadline::in_secs(10);
        let code = stop(vec![(sel, None)], None, deadline, vms::StopHow::Graceful);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(!stand_in.alive());
        untouched();
        let project = Selector::Dir {
            dir: homes.dir().to_path_buf(),
            below: true,
        };
        let deadline = vms::Deadline::in_secs(10);
        vms::stop_cmd(Some(project), false, deadline, vms::StopHow::Graceful).unwrap();
        untouched();
    }

    /// A run whose `--state-dir` is in the dev base is a run: forgotten, its dir and what
    /// else is in it kept.
    #[test]
    fn a_run_in_the_dev_base_keeps_its_dir() {
        let homes = crate::dev::testutil::Homes::new("rm-devbase");
        let dir = crate::dev::plan::dev_state_base().unwrap().join("scratch");
        std::fs::create_dir_all(&dir).unwrap();
        let dir = vms::canonical(&dir);
        homes.name(&dir, "app");
        std::fs::write(dir.join(crate::names::RECIPE), b"{}").unwrap();
        std::fs::write(dir.join("notes.txt"), b"keep").unwrap();
        let p = plan_one(&os("app"), false).unwrap();
        assert_eq!((p.t.kind, p.removal), (Kind::Run, Removal::Forget));
        assert!(deleted(&[os("app")]));
        assert!(dir.join("notes.txt").exists() && !dir.join(crate::names::RECIPE).exists());
        assert_eq!(crate::names::Index::open().unwrap().name_of(&dir), None);
    }

    /// A run recipe or an unreadable dev identity prevents reset from removing data.
    #[test]
    fn reset_takes_only_a_dir_known_to_be_a_dev_environment() {
        let homes = crate::dev::testutil::Homes::new("reset-own");
        let dir = crate::dev::plan::dev_state_base().unwrap().join("scratch");
        std::fs::create_dir_all(dir.join("editor")).unwrap();
        let dir = vms::canonical(&dir);
        let identity = serde_json::json!({ "digest": "d", "booted_secs": 0, "manifest": {} });
        std::fs::write(dir.join("dev.json"), identity.to_string()).unwrap();
        std::fs::write(dir.join(crate::names::RECIPE), b"{}").unwrap();
        homes.name(&dir, "app");
        let o = crate::dev::prune::Options::default();
        let err = format!("{:#}", reset(&os("app"), &o).unwrap_err());
        assert!(
            err.contains("app is not reset") && err.contains("run's"),
            "{err}"
        );
        std::fs::remove_file(dir.join(crate::names::RECIPE)).unwrap();
        std::fs::write(dir.join("dev.json"), b"{}").unwrap();
        let err = format!("{:#}", reset(&os("app"), &o).unwrap_err());
        assert!(err.contains("app is not reset"), "{err}");
        assert!(dir.join("editor").is_dir());
    }

    /// A dir put in place of the one planned on, after it was locked, loses nothing: the
    /// recipe goes from the dir planned on, and the name stays.
    #[test]
    fn forget_acts_on_the_dir_it_holds() {
        let homes = crate::dev::testutil::Homes::new("rm-swap");
        let mine = homes.dir().join("mine");
        std::fs::create_dir_all(&mine).unwrap();
        homes.name(&mine, "mine");
        std::fs::write(mine.join(crate::names::RECIPE), b"{}").unwrap();
        let p = plan_one(&os("mine"), false).unwrap();
        assert_eq!(p.removal, Removal::Forget);
        let lock = hold(&p).unwrap();
        let moved = homes.dir().join("moved");
        std::fs::rename(&mine, &moved).unwrap();
        std::fs::create_dir(&mine).unwrap();
        std::fs::write(mine.join(crate::names::RECIPE), b"{}").unwrap();
        let err = remove(&p, lock).unwrap_err();
        assert!(format!("{err:#}").contains("another directory"), "{err:#}");
        assert!(mine.join(crate::names::RECIPE).exists());
        assert!(!moved.join(crate::names::RECIPE).exists());
        let idx = crate::names::Index::open().unwrap();
        assert_eq!(idx.lookup("mine"), Some(vms::canonical(&mine)));
    }

    /// Two services of one VM, and a target named twice, are deleted in one go: one lock
    /// for their state dir.
    #[test]
    fn delete_takes_one_lock_per_state_dir() {
        let homes = crate::dev::testutil::Homes::new("rm-siblings");
        let dir = stopped_run(&homes, "app", &["db", "cache"]);
        for s in ["svc-db", "svc-cache"] {
            std::fs::create_dir_all(dir.join(s)).unwrap();
        }
        let refs = [os("app/db"), os("app/cache"), os("app/db")];
        assert!(deleted(&refs));
        assert!(!dir.join("svc-db").exists() && !dir.join("svc-cache").exists());
        assert!(dir.exists());
    }

    /// One VM in use deletes none; a plan gone stale removes nothing it did not plan on.
    #[test]
    fn delete_checks_every_vm_first_and_acts_only_on_what_it_planned() {
        let homes = crate::dev::testutil::Homes::new("rm-stale");
        let a = stopped_run(&homes, "a", &[]);
        let b = stopped_run(&homes, "b", &[]);
        let busy = crate::dev::list::try_lock_state_dir(&b).unwrap();
        assert_eq!(
            delete(&[os("a"), os("b")], false, true, false, O),
            ExitCode::from(1)
        );
        assert!(a.exists() && b.exists());
        drop(busy);
        // Replaced since the plan: refused.
        let p = plan_one(&os("a"), false).unwrap();
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::create_dir(&a).unwrap();
        let err = hold(&p).unwrap_err();
        assert!(format!("{err:#}").contains("another directory"), "{err:#}");
        // Gone, and its name taken for another dir since: that name stays.
        std::fs::remove_dir_all(&a).unwrap();
        let p = plan_one(&os("a"), false).unwrap();
        assert!(p.dir.is_none());
        let idx = crate::names::Index::open().unwrap();
        idx.release(&a).unwrap();
        let other = homes.dir().join("other");
        std::fs::create_dir(&other).unwrap();
        homes.name(&other, "a");
        assert!(hold(&p).unwrap().is_none());
        assert!(remove(&p, None).unwrap().starts_with("forgot a"));
        assert_eq!(idx.lookup("a"), Some(vms::canonical(&other)));
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
        let _registered = vms::register(run_of(&dir, &stand_in, &[]));
        let t = resolve(&os(&stand_in.id().to_string()), Among::ProjectVm).unwrap();
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
            let _registered = vms::register(run_of(&dir, &stand_in, &[]));
            let err = format!("{:#}", restart_one(&t, O).unwrap_err());
            assert!(err.contains(said), "{err}");
            assert!(stand_in.alive() && running_on(&dir).is_some());
        }
    }
}
