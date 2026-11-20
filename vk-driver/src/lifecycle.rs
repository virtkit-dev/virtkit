//! `vk start | stop | restart | rm | reset | rename`: the lifecycle of a VM `vk list` names,
//! whatever made it. A dev environment goes through `vk dev` (its config is in its
//! workspace), a run through the recipe it left (`run.json`), a compose service through its
//! primary's service manager.
//!
//! [`plan`] is pure: it says what a verb does to a target in a given state, so a test pins
//! every kind and state; [`run`] carries the plan out.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use crate::vmlist::Kind;
use crate::vms::{self, Ref, VmEntry};

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

/// The one VM of `found` a directory REF means, `None` when there is none. A REF is one VM
/// at most: with several, [`Among::ProjectVm`] takes the project's `dev` environment if
/// that settles it, and anything else is refused with their names.
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

/// What a state dir is: a dev environment's when it sits in the dev base, else a run's.
fn kind_of(dir: &Path) -> Result<Kind> {
    let dev_base = crate::dev::plan::dev_state_base().map(|b| vms::canonical(&b))?;
    Ok(
        match vms::canonical(dir).parent() == Some(dev_base.as_path()) {
            true => Kind::Dev,
            false => Kind::Run,
        },
    )
}

/// The named VMs, running or not, that the directory `dir` (canonical) stands for: the one
/// whose state dir it is, else every one whose project it is — a run's recorded project
/// directory, a dev environment's workspace.
fn named_at(idx: &crate::names::Index, dir: &Path) -> Result<Vec<Candidate>> {
    let mut found = Vec::new();
    for (name, state_dir) in idx.all() {
        if !state_dir.is_dir() {
            continue;
        }
        let (workspace, environment) = vms::dev_identity(&state_dir);
        let candidate = Candidate {
            name,
            kind: kind_of(&state_dir)?,
            environment,
            dir: state_dir.clone(),
        };
        if vms::canonical(&state_dir) == dir {
            return Ok(vec![candidate]);
        }
        let project = crate::names::Recipe::read(&state_dir)
            .ok()
            .flatten()
            .map(|r| r.project_dir)
            .or(workspace)
            .or_else(|| vms::last_entry(&state_dir).and_then(|e| e.project_dir));
        if project.is_some_and(|p| vms::canonical(&p) == dir) {
            found.push(candidate);
        }
    }
    Ok(found)
}

/// Resolve a REF to one VM, running or not: a name or `NAME/SERVICE`; a state directory, or
/// a project directory, which means the project's VM and never its compose services; or
/// the pid of a running VM. Read as every VM command reads it
/// ([`vms::Selector::from_ref`]), so a word means the same VM to `start` as to `stop`.
pub fn resolve(arg: &OsStr, among: Among) -> Result<Target> {
    let idx = crate::names::Index::open()?;
    let (sel, service) = vms::Selector::from_ref(Ref::parse(arg)?, false)?;
    let known = match &sel {
        vms::Selector::Named { name, dir } => Some(Candidate {
            name: idx.name_of(dir).unwrap_or_else(|| name.clone()),
            kind: kind_of(dir)?,
            environment: None,
            dir: dir.clone(),
        }),
        vms::Selector::Dir { dir, .. } => {
            let dir = vms::canonical(dir);
            pick_one(named_at(&idx, &dir)?, among, &dir.display().to_string())?
        }
        vms::Selector::Pid(_) => None,
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
            let Some(name) = idx.name_of(&entry.state_dir).or(own.map(str::to_string)) else {
                bail!(
                    "the VM {} has no name: it is not known once it stops (`vk stop {}`)",
                    entry.pid,
                    entry.pid
                );
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

/// One step of a verb.
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
    /// stop the dev environment, publishers and all (`vk dev stop`)
    DevStop,
    /// SIGTERM the run and wait
    RunStop,
    /// remove the dev environment's state (`vk dev gc`)
    DevRemove,
    /// remove a managed run's state dir
    RemoveDir,
    /// forget a run whose state dir is the user's: its recipe and last entry go, the dir stays
    Forget,
    /// remove a service's `svc-<name>/`
    RemoveService,
    /// say so and do nothing
    Nothing(String),
}

/// The verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `build`: build what is not built yet, as `up` does; otherwise boot only what is
    Start {
        build: bool,
    },
    Stop,
    Delete {
        force: bool,
    },
}

/// What `verb` does to `t`, given whether its primary and (for a service) the service run,
/// and whether its state dir is one `vk` manages.
pub fn plan(
    verb: Verb,
    t: &Target,
    primary_up: bool,
    service_up: bool,
    managed: bool,
) -> Result<Vec<Step>> {
    use Step::*;
    let dev = t.kind == Kind::Dev;
    Ok(match (verb, &t.service) {
        (Verb::Start { .. }, None) if primary_up => {
            vec![Nothing(format!("{} is running", t.shown()))]
        }
        (Verb::Start { .. }, None) => vec![if dev { DevUp } else { Replay }],
        (Verb::Start { .. }, Some(_)) => {
            let mut steps = Vec::new();
            if !primary_up {
                steps.push(if dev { DevUp } else { Replay });
            }
            steps.push(if dev {
                DevService { up: true }
            } else {
                Control { up: true }
            });
            steps
        }
        (Verb::Stop, None) if !primary_up && !dev => {
            vec![Nothing(format!("{} is not running", t.shown()))]
        }
        // `vk dev stop` also takes down what an environment publishes when it is down.
        (Verb::Stop, None) => vec![if dev { DevStop } else { RunStop }],
        (Verb::Stop, Some(_)) if !primary_up || !service_up => {
            vec![Nothing(format!("{} is not running", t.shown()))]
        }
        (Verb::Stop, Some(_)) => vec![if dev {
            DevService { up: false }
        } else {
            Control { up: false }
        }],
        (Verb::Delete { force }, service) => {
            let up = match service {
                None => primary_up,
                Some(_) => primary_up && service_up,
            };
            let mut steps = Vec::new();
            if up {
                if !force {
                    bail!(
                        "{} is running — `vk stop {}` first, or `vk delete -f`",
                        t.shown(),
                        t.shown()
                    );
                }
                steps.extend(plan(Verb::Stop, t, primary_up, service_up, managed)?);
            }
            steps.push(match (service, dev, managed) {
                (Some(_), _, _) => RemoveService,
                (None, true, _) => DevRemove,
                (None, false, true) => RemoveDir,
                (None, false, false) => Forget,
            });
            steps
        }
    })
}

/// What `verb` does to `t` as it is now.
fn steps_for(verb: Verb, t: &Target) -> Result<Vec<Step>> {
    let entry = running_on(&t.dir);
    let up = service_up(entry.as_ref(), t.service.as_deref());
    plan(verb, t, entry.is_some(), up, managed(&t.dir))
}

/// Hold `dir`'s lock — the one a run holds from before it pulls until it exits — while
/// something of it is removed, or refuse: a run that registers no VM (compose up, a boot
/// still under way) uses the directory all the same. `None` for a directory that is gone.
fn hold_unused(t: &Target) -> Result<Option<std::fs::File>> {
    if !t.dir.exists() {
        return Ok(None);
    }
    match crate::dev::list::try_lock_state_dir(&t.dir) {
        Some(lock) => Ok(Some(lock)),
        None => {
            let held = crate::dev::lock_holder(&t.dir).unwrap_or_else(|| "another vk".into());
            bail!("{} is in use by {held} — stop that first", t.name)
        }
    }
}

/// Remove everything in the service directory `dir` but its sockets. The run the service
/// belongs to is up: its switch bound the service's network socket there when it started
/// and binds it only then, so the directory and that socket stay for the next start.
fn empty_but_sockets(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_socket() {
            continue;
        }
        match kind.is_dir() {
            true => std::fs::remove_dir_all(entry.path())?,
            false => std::fs::remove_file(entry.path())?,
        }
    }
    Ok(())
}

/// Whether `dir` is a state dir `vk` made (under the dev or run base), and so may delete.
fn managed(dir: &Path) -> bool {
    let parent = vms::canonical(dir).parent().map(Path::to_path_buf);
    let base = |b: Result<PathBuf>| b.ok().map(|b| vms::canonical(&b));
    parent.is_some()
        && (parent == base(crate::dev::plan::dev_state_base())
            || parent == base(crate::names::run_base()))
}

/// The `vk dev` options that select the dev environment on `dir`, as its `dev.json` records
/// it: its workspace, the config file it was booted from — which `--dev-config` may have
/// taken from elsewhere than the workspace's own — and its environment.
fn dev_selection(dir: &Path) -> Result<Vec<String>> {
    let path = dir.join("dev.json");
    let identity: crate::dev::Identity = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("reading {}", path.display()))?;
    let (workspace, environment) = dev_identity(dir)?;
    Ok(selection_args(
        &workspace,
        identity.manifest.get("config").and_then(|v| v.as_str()),
        &environment,
    ))
}

/// `dev --workspace W [--dev-config C] --environment E`: the config file only when one was
/// recorded, so an environment recorded before it was still finds its workspace's own.
fn selection_args(workspace: &str, config: Option<&str>, environment: &str) -> Vec<String> {
    let mut args = vec!["dev".to_string(), "--workspace".into(), workspace.into()];
    if let Some(config) = config {
        args.extend(["--dev-config".to_string(), config.into()]);
    }
    args.extend(["--environment".to_string(), environment.into()]);
    args
}

/// A dev environment's workspace and environment, as its `dev.json` records them.
fn dev_identity(dir: &Path) -> Result<(String, String)> {
    let path = dir.join("dev.json");
    let identity: crate::dev::Identity = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("reading {}", path.display()))?;
    let text = |key: &str| {
        identity
            .manifest
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    let workspace = text("workspace").context("its dev.json records no workspace")?;
    if !Path::new(&workspace).is_dir() {
        bail!("its workspace {workspace} is gone");
    }
    Ok((
        workspace,
        text("environment").unwrap_or_else(|| "dev".into()),
    ))
}

/// Run this `vk` with `args`, in `cwd`, its output ours; fail unless it succeeds.
fn vk(args: &[String], cwd: Option<&Path>, from_recipe: bool) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the running vk")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    if from_recipe {
        cmd.env(crate::FROM_RECIPE_ENV, "1");
    }
    let status = cmd.status().context("running vk")?;
    if !status.success() {
        bail!("`vk {}` {status}", args.join(" "));
    }
    Ok(())
}

/// Carry out `steps` on `t`. A start boots only what is already built, unless `build`.
fn execute(
    t: &Target,
    steps: &[Step],
    timeout: Option<u64>,
    build: bool,
    how: vms::StopHow,
) -> Result<String> {
    let start = if build { "up" } else { "start" };
    let mut out = String::new();
    for step in steps {
        match step {
            Step::Nothing(what) => out.push_str(&format!("{what}\n")),
            Step::DevUp => {
                let mut args =
                    dev_selection(&t.dir).with_context(|| format!("cannot start {}", t.name))?;
                args.push(start.into());
                vk(&args, None, false)?;
            }
            Step::DevService { up } => {
                let mut args = dev_selection(&t.dir)?;
                let service = t.service.clone().unwrap_or_default();
                let op = if *up { start } else { "stop" };
                args.extend([op.to_string(), "--service".into(), service]);
                vk(&args, None, false)?;
            }
            Step::Replay => {
                let Some(recipe) = crate::names::Recipe::read(&t.dir)? else {
                    bail!(
                        "{} recorded no way to run it again (no {}): run it with `vk run` once more",
                        t.name,
                        crate::names::RECIPE
                    );
                };
                let mut args = recipe.replay_args(&t.dir, &t.name);
                if !build {
                    let at = args
                        .iter()
                        .position(|a| a == "--detach")
                        .unwrap_or(args.len());
                    args.insert(at, "--require-cached".into());
                }
                vk(&args, Some(&recipe.cwd), true)?;
            }
            Step::Control { up } => {
                let entry =
                    running_on(&t.dir).with_context(|| format!("{} is not running", t.name))?;
                let ctl = vms::control_socket(&entry)
                    .with_context(|| format!("{} runs no compose services", t.name))?;
                let unit = t.service.clone().unwrap_or_default();
                let req = match up {
                    true => vk_core::fleetctl::Request::Start {
                        unit,
                        cached: !build,
                    },
                    false => vk_core::fleetctl::Request::Stop { unit },
                };
                let timeout = timeout.filter(|_| !up).map(std::time::Duration::from_secs);
                let reply = vms::control(&ctl, &req, timeout, |line| eprintln!("{line}"))?;
                if !reply.ok {
                    bail!("{}: {}", t.shown(), reply.message);
                }
                out.push_str(&format!(
                    "{} {}\n",
                    if *up { "started" } else { "stopped" },
                    t.shown()
                ));
            }
            Step::DevStop => {
                let stopped = crate::dev::stop_how(&t.dir, timeout, how)?;
                out.push_str(&stopped.report);
                if !stopped.all_down {
                    bail!("{out}{} did not stop", t.name);
                }
            }
            Step::RunStop => {
                let Some(entry) = running_on(&t.dir) else {
                    out.push_str(&format!("{} is not running\n", t.name));
                    continue;
                };
                let (line, down) = vms::stop_entry_how(&entry, timeout, how)
                    .with_context(|| format!("{} is held by another run", t.name))?;
                out.push_str(&line);
                if !down {
                    bail!("{out}");
                }
            }
            Step::DevRemove if !t.dir.exists() => {
                // A name left on a directory something else removed: only the name goes.
                let idx = crate::names::Index::open()?;
                idx.release(&t.dir);
                idx.remove(&t.name);
                out.push_str(&format!("forgot {} (its state dir was gone)\n", t.name));
            }
            Step::DevRemove => {
                let dir_name = t.dir.file_name().unwrap_or_default().to_string_lossy();
                // `vk delete` asked already (or was told not to): no second question.
                let code = crate::dev::cli::dev_gc(true, false, &[dir_name.into_owned()], false);
                if code != ExitCode::SUCCESS {
                    bail!("{} was not removed", t.name);
                }
            }
            Step::RemoveDir => {
                let idx = crate::names::Index::open()?;
                if !t.dir.exists() {
                    // A name left on a directory something else removed: only the name goes.
                    idx.remove(&t.name);
                    out.push_str(&format!("forgot {} (its state dir was gone)\n", t.name));
                    continue;
                }
                let _unused = hold_unused(t)?;
                std::fs::remove_dir_all(&t.dir)
                    .with_context(|| format!("removing {}", t.dir.display()))?;
                idx.release(&t.dir);
                out.push_str(&format!("removed {}\n", t.name));
            }
            Step::Forget => {
                let _unused = hold_unused(t)?;
                for f in [crate::names::RECIPE, vms::LAST] {
                    let _ = std::fs::remove_file(t.dir.join(f));
                }
                crate::names::Index::open()?.release(&t.dir);
                out.push_str(&format!(
                    "removed {} (its state dir {} is yours and stays)\n",
                    t.name,
                    t.dir.display()
                ));
            }
            Step::RemoveService => {
                let service = t.service.clone().unwrap_or_default();
                let dir = t.dir.join(format!("svc-{service}"));
                // With its run up, the directory is still that run's: only what the service
                // left in it goes. Otherwise nothing may be using the VM's state dir.
                let run_up = running_on(&t.dir).is_some();
                let _unused = match run_up {
                    true => None,
                    false => hold_unused(t)?,
                };
                let removed = match run_up {
                    true => empty_but_sockets(&dir),
                    false => std::fs::remove_dir_all(&dir),
                };
                match removed {
                    Ok(()) => out.push_str(&format!("removed {}\n", t.shown())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        out.push_str(&format!("{} holds no state\n", t.shown()))
                    }
                    Err(e) => {
                        return Err(e).with_context(|| format!("removing {}", dir.display()));
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Whether the service `name` of the running `entry` is up.
fn service_up(entry: Option<&VmEntry>, name: Option<&str>) -> bool {
    let (Some(entry), Some(name)) = (entry, name) else {
        return false;
    };
    let Some(ctl) = vms::control_socket(entry) else {
        return false;
    };
    let req = vk_core::fleetctl::Request::Status { unit: name.into() };
    vms::control(&ctl, &req, Some(std::time::Duration::from_secs(5)), |_| {}).is_ok_and(|r| {
        r.ok && r
            .units
            .iter()
            .any(|u| u.name == name && u.state != "stopped")
    })
}

/// `vk start|stop` on each REF in turn; the exit status says whether every one did.
pub fn run(verb: Verb, refs: &[std::ffi::OsString], timeout: u64) -> ExitCode {
    run_how(verb, refs, Some(timeout), vms::StopHow::Graceful)
}

/// [`run`], a stop going about it as `how` says. Only a VM's own run is signalled: a
/// compose service is stopped by its service manager, which has one way to do it.
pub fn run_how(
    verb: Verb,
    refs: &[std::ffi::OsString],
    timeout: Option<u64>,
    how: vms::StopHow,
) -> ExitCode {
    let build = matches!(verb, Verb::Start { build: true });
    let mut ok = true;
    for r in refs {
        // A project directory means its own VM: one REF starts or stops one VM at most.
        let result = resolve(r, Among::ProjectVm).and_then(|t| {
            if how != vms::StopHow::Graceful && t.service.is_some() {
                bail!(
                    "{} is a compose service, stopped by its VM's service manager: --force \
                     and --kill act on a VM's own run (`vk stop --force {}`)",
                    t.shown(),
                    t.name
                );
            }
            let steps = steps_for(verb, &t)?;
            execute(&t, &steps, timeout, build, how)
        });
        match result {
            Ok(report) => print!("{report}"),
            Err(e) => {
                eprintln!("vk: {e:#}");
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// What one REF given to `vk stop` comes to.
enum Stopping {
    /// a compose service, stopped through its VM's service manager
    Service(Target),
    /// running VMs to stop, and what to say besides (a named VM that is not running)
    Vms(Vec<VmEntry>, String),
}

/// What `vk stop` is to stop for one REF: a compose service, or the running VMs the REF
/// selects — a name's own VM, or every VM a pid or a directory matches, below it too with
/// `recursive`. `Err` when the REF selects nothing that can be stopped.
fn stopping(arg: &OsStr, recursive: bool) -> Result<Stopping> {
    let (sel, service) = vms::Selector::from_ref(Ref::parse(arg)?, recursive)?;
    if service.is_some() {
        return Ok(Stopping::Service(resolve(arg, Among::ProjectVm)?));
    }
    let (name, dir) = match sel {
        vms::Selector::Named { name, dir } => (name, dir),
        other => {
            let (matched, none) = vms::running_selected(other)?;
            if matched.is_empty() {
                bail!("{}", none.trim_end());
            }
            return Ok(Stopping::Vms(matched, String::new()));
        }
    };
    match running_on(&dir) {
        Some(entry) if vms::held_by_another(&entry) => {
            bail!("{name} is held by another run")
        }
        Some(entry) => Ok(Stopping::Vms(vec![entry], String::new())),
        None => {
            // What an environment published can outlive it on record: cleared here, as
            // `vk dev stop` does for one that is already down.
            if kind_of(&dir)? == Kind::Dev {
                crate::publish::stop_all_quietly(&dir, std::time::Duration::from_secs(5));
            }
            Ok(Stopping::Vms(
                Vec::new(),
                format!("{name} is not running\n"),
            ))
        }
    }
}

/// `vk stop REF…`: every REF is resolved first, then every VM is told to stop at once, and
/// `timeout` — seconds, `None` for as long as it takes — bounds the whole command rather
/// than each VM. Compose services go through their service managers, one after the other,
/// within the same bound. Exits 2 when a REF selects nothing, 1 when a VM did not stop.
pub fn stop_all(
    refs: &[std::ffi::OsString],
    recursive: bool,
    timeout: Option<u64>,
    how: vms::StopHow,
) -> ExitCode {
    let started = std::time::Instant::now();
    let left = || timeout.map(|t| t.saturating_sub(started.elapsed().as_secs()));
    let (mut found, mut all_down) = (true, true);
    let mut entries: Vec<VmEntry> = Vec::new();
    let mut services = Vec::new();
    for r in refs {
        match stopping(r, recursive) {
            Ok(Stopping::Service(t)) => services.push(t),
            Ok(Stopping::Vms(vms, note)) => {
                print!("{note}");
                for e in vms {
                    if !entries.iter().any(|known| known.state_dir == e.state_dir) {
                        entries.push(e);
                    }
                }
            }
            Err(e) => {
                eprintln!("vk: {e:#}");
                found = false;
            }
        }
    }
    for t in &services {
        let stopped = match how {
            vms::StopHow::Graceful => {
                steps_for(Verb::Stop, t).and_then(|steps| execute(t, &steps, left(), false, how))
            }
            _ => Err(anyhow::anyhow!(
                "{} is a compose service, stopped by its VM's service manager: --force and \
                 --kill act on a VM's own run (`vk stop --force {}`)",
                t.shown(),
                t.name
            )),
        };
        match stopped {
            Ok(report) => print!("{report}"),
            Err(e) => {
                eprintln!("vk: {e:#}");
                all_down = false;
            }
        }
    }
    let (report, down) = vms::stop_reports(&entries, left(), how);
    print!("{report}");
    match (found, all_down && down) {
        (false, _) => ExitCode::from(2),
        (true, false) => ExitCode::from(1),
        (true, true) => ExitCode::SUCCESS,
    }
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
        let dir = t.dir.display();
        match self {
            Step::Nothing(what) => what.clone(),
            Step::DevStop
            | Step::RunStop
            | Step::Control { up: false }
            | Step::DevService { up: false } => format!("stop {name}"),
            Step::DevRemove => format!(
                "delete dev environment {name}{}: its state dir {dir}, storage and all",
                with_services(&t.dir)
            ),
            Step::RemoveDir => format!(
                "delete {name}{}: its state dir {dir}",
                with_services(&t.dir)
            ),
            Step::Forget => {
                format!("forget {name}: its recipe and name go, its state dir {dir} (yours) stays")
            }
            Step::RemoveService => format!(
                "delete {name}: what it keeps in {}",
                t.dir
                    .join(format!("svc-{}", t.service.as_deref().unwrap_or_default()))
                    .display()
            ),
            Step::DevUp
            | Step::Replay
            | Step::Control { up: true }
            | Step::DevService { up: true } => format!("start {name}"),
        }
    }
}

/// ` and its services a, b` for the compose services that left state in the VM's state dir
/// `dir`, which goes with it; empty when there is none.
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

/// `vk delete REF…`: every REF is resolved and planned first, so one that cannot go (no such
/// VM, or running without `--force`) leaves every other one in place. Then, per `gate`, what
/// would go is listed (`--dry-run`), asked about, refused, or removed.
pub fn delete(
    refs: &[std::ffi::OsString],
    force: bool,
    yes: bool,
    dry_run: bool,
    timeout: u64,
) -> ExitCode {
    let mut planned = Vec::new();
    let mut ok = true;
    for r in refs {
        let result = resolve(r, Among::One).and_then(|t| {
            let steps = steps_for(Verb::Delete { force }, &t)?;
            Ok((t, steps))
        });
        match result {
            Ok(p) => planned.push(p),
            Err(e) => {
                eprintln!("vk: {e:#}");
                ok = false;
            }
        }
    }
    let list: String = planned
        .iter()
        .flat_map(|(t, steps)| steps.iter().map(move |s| format!("  {}\n", s.describe(t))))
        .collect();
    let gate = gate(yes, force, dry_run, crate::dev::on_terminal());
    if gate == Gate::DryRun {
        print!("would:\n{list}");
        return if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    if !ok {
        eprintln!("vk: nothing was deleted");
        return ExitCode::from(1);
    }
    match gate {
        Gate::Refuse => {
            eprint!(
                "vk delete would:\n{list}vk: nothing was deleted: not on a terminal to ask, \
                 so pass --yes (or --force)\n"
            );
            return ExitCode::from(1);
        }
        Gate::Ask => {
            eprint!("vk delete will:\n{list}");
            match crate::dev::ask_on_terminal("go ahead?") {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("vk: nothing was deleted");
                    return ExitCode::from(1);
                }
                Err(e) => {
                    eprintln!("vk: {e:#}");
                    return ExitCode::from(1);
                }
            }
        }
        Gate::Go | Gate::DryRun => {}
    }
    for (t, steps) in &planned {
        match execute(t, steps, Some(timeout), false, vms::StopHow::Graceful) {
            Ok(report) => print!("{report}"),
            Err(e) => {
                eprintln!("vk: {e:#}");
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `vk restart REF…`: stop, then start, each in turn. One that does not stop is not
/// started; the others still are, and the exit status says whether every one restarted.
pub fn restart(refs: &[std::ffi::OsString], build: bool, timeout: u64) -> ExitCode {
    let mut ok = true;
    for r in refs {
        let one = std::slice::from_ref(r);
        ok &= run(Verb::Stop, one, timeout) == ExitCode::SUCCESS
            && run(Verb::Start { build }, one, timeout) == ExitCode::SUCCESS;
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `vk reset REF`: remove a dev environment's boot images or persistent data, as
/// `vk dev prune` does in its workspace. Only a dev environment has either.
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
            "{} is a run, not a dev environment: `vk reset` has nothing to reset there \
             (`vk delete {}` removes it)",
            t.name,
            t.name
        );
    }
    let dir_name = t.dir.file_name().unwrap_or_default().to_string_lossy();
    crate::dev::prune::run_by_name(&dir_name, options)
}

/// `vk rename OLD NEW`.
pub fn rename(old: &str, new: &str) -> Result<String> {
    let idx = crate::names::Index::open()?;
    if idx.lookup(old).is_none() {
        // A dev environment still known by its state dir's own name gets its first name here.
        let Some(dir) = crate::names::resolve(old)? else {
            bail!("no VM is named {old}");
        };
        idx.claim_exact(&dir, new)?;
    } else {
        idx.rename(old, new)?;
    }
    Ok(format!("renamed {old} to {new}\n"))
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

    fn steps(
        verb: Verb,
        kind: Kind,
        service: Option<&str>,
        up: bool,
        svc_up: bool,
        managed: bool,
    ) -> Vec<Step> {
        plan(verb, &target(kind, service), up, svc_up, managed).unwrap()
    }

    #[test]
    fn start_boots_by_kind_and_a_service_after_its_primary() {
        use Step::*;
        assert_eq!(
            steps(
                Verb::Start { build: false },
                Kind::Dev,
                None,
                false,
                false,
                true
            ),
            [DevUp]
        );
        assert_eq!(
            steps(
                Verb::Start { build: false },
                Kind::Run,
                None,
                false,
                false,
                true
            ),
            [Replay]
        );
        assert!(matches!(
            steps(
                Verb::Start { build: false },
                Kind::Run,
                None,
                true,
                false,
                true
            )[..],
            [Nothing(_)]
        ));
        assert_eq!(
            steps(
                Verb::Start { build: false },
                Kind::Dev,
                Some("db"),
                false,
                false,
                true
            ),
            [DevUp, DevService { up: true }]
        );
        assert_eq!(
            steps(
                Verb::Start { build: false },
                Kind::Run,
                Some("db"),
                true,
                false,
                true
            ),
            [Control { up: true }]
        );
    }

    #[test]
    fn stop_goes_through_dev_for_an_environment_and_skips_what_is_down() {
        use Step::*;
        assert_eq!(
            steps(Verb::Stop, Kind::Dev, None, false, false, true),
            [DevStop]
        );
        assert_eq!(
            steps(Verb::Stop, Kind::Run, None, true, false, true),
            [RunStop]
        );
        assert!(matches!(
            steps(Verb::Stop, Kind::Run, None, false, false, true)[..],
            [Nothing(_)]
        ));
        assert_eq!(
            steps(Verb::Stop, Kind::Dev, Some("db"), true, true, true),
            [DevService { up: false }]
        );
        assert!(matches!(
            steps(Verb::Stop, Kind::Run, Some("db"), true, false, true)[..],
            [Nothing(_)]
        ));
    }

    #[test]
    fn rm_refuses_what_runs_unless_forced_and_never_deletes_a_users_dir() {
        use Step::*;
        assert!(
            plan(
                Verb::Delete { force: false },
                &target(Kind::Run, None),
                true,
                false,
                true
            )
            .is_err()
        );
        assert_eq!(
            steps(
                Verb::Delete { force: true },
                Kind::Run,
                None,
                true,
                false,
                true
            ),
            [RunStop, RemoveDir]
        );
        assert_eq!(
            steps(
                Verb::Delete { force: false },
                Kind::Run,
                None,
                false,
                false,
                false
            ),
            [Forget]
        );
        assert_eq!(
            steps(
                Verb::Delete { force: false },
                Kind::Dev,
                None,
                false,
                false,
                true
            ),
            [DevRemove]
        );
        assert_eq!(
            steps(
                Verb::Delete { force: false },
                Kind::Run,
                Some("db"),
                true,
                false,
                true
            ),
            [RemoveService]
        );
        assert!(
            plan(
                Verb::Delete { force: false },
                &target(Kind::Run, Some("db")),
                true,
                true,
                true
            )
            .is_err()
        );
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
        use Step::*;
        let run = target(Kind::Run, None);
        assert_eq!(RunStop.describe(&run), "stop app");
        assert_eq!(RemoveDir.describe(&run), "delete app: its state dir /s/app");
        assert!(Forget.describe(&run).contains("/s/app (yours) stays"));
        let dev = target(Kind::Dev, None);
        assert!(
            DevRemove
                .describe(&dev)
                .starts_with("delete dev environment app")
        );
        let svc = target(Kind::Run, Some("db"));
        assert_eq!(
            RemoveService.describe(&svc),
            "delete app/db: what it keeps in /s/app/svc-db"
        );
        assert_eq!(Control { up: false }.describe(&svc), "stop app/db");
    }
}
