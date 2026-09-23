//! Doing something to the selected environment, rather than only looking at it.
//!
//! **Every action re-execs this same `vk`.** Not one of them calls into [`crate::dev`]
//! directly, and the reasons are structural rather than stylistic: `vk dev code` ends in
//! `execvp`, which would replace the dashboard with the editor; a boot expects the fork
//! `main` performs *before* the Tokio runtime exists, and forking a live runtime is
//! undefined behaviour; [`crate::dev::boot`] is `async` while this loop is not. Re-execing
//! also means a `vk dev up` that dies takes nothing of the dashboard's with it. The binary
//! is [`std::env::current_exe`] and never `vk` off `PATH` — the dashboard drives *this*
//! `vk`, whichever one the reader started.
//!
//! **Every action names the environment it acts on.** A `vk dev` command otherwise resolves
//! the workspace from the process's own working directory, which is wherever the reader
//! happened to open the dashboard — so `--workspace` and `--environment` are passed from the
//! row every time, with `--dev-config` where it recorded the config it booted from. The pair
//! is the identity: two environments over one checkout differ only in the name, and a
//! command given the directory alone would act on whichever of them came first. A stop and a
//! removal name the state directory instead, which is that identity in one word and needs
//! neither the checkout nor its config.
//!
//! **An environment that cannot be acted on says so before the key is pressed**, with the
//! reason in words. The facts are all in the row — [`Refusal`] is the list of them.
//!
//! **What cannot be undone asks first**, and what it asks with is `vk dev gc`'s own listing
//! of what is inside the directory, produced in-process and read-only. Only the removal
//! re-execs.
//!
//! **Nothing here blocks the thread that draws.** A quiet action runs on a thread of its
//! own and its outcome arrives as an [`Event`]; the two that want the terminal are handed
//! back to the loop, which is the only place that owns it.

use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;

use anyhow::{Context, Result};

use super::envs::Env;
use super::poll::{self, Event};
use crate::dev::list::Flag;

/// Something the dashboard can do to the selected environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Stop,
    Up,
    Refresh,
    Shell,
    Code,
    /// the guest's own view of itself, which is a panel of its own
    Atop,
    Remove,
}

/// How much asking an action deserves before it happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Weight {
    /// Changes nothing; it only shows more than the dashboard can.
    ReadOnly,
    /// Costs time and nothing else. Runs on the keystroke.
    Reversible,
    /// Destroys something. Stops and asks, naming what goes.
    Destructive,
}

/// Why an action cannot be offered for the selected environment.
///
/// Every one of these is a fact the row already carries, so the menu can say it before the
/// key is pressed rather than letting `vk` explain it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// There is no VM to act on.
    NotRunning,
    /// It is already in the state the action would put it in.
    AlreadyRunning,
    /// There is a VM, and what was asked for cannot happen while there is.
    Running,
    /// The environment recorded no checkout, so there is no workspace to name.
    NoWorkspace,
    /// It recorded one and it is not on this host any more.
    WorkspaceGone,
    /// A bare `vk run`, which `vk dev` has nothing to say about.
    NotAnEnvironment,
}

impl Refusal {
    /// The long form, for the key bar: a reader who pressed a greyed key is asking for the
    /// reason, and there is room for a real one down there.
    pub(crate) fn why(self) -> &'static str {
        match self {
            Self::NotRunning => "it is not running",
            Self::AlreadyRunning => "it is already running",
            Self::Running => "it is running — stop it first, and then it can be removed",
            Self::NoWorkspace => {
                "this environment recorded no checkout, so there is nothing to run a \
                 workspace command in"
            }
            Self::WorkspaceGone => {
                "its checkout is gone from this host — d removes what it left behind"
            }
            Self::NotAnEnvironment => "this is a vk run, not a dev environment",
        }
    }

    /// The short form, for the menu row, where the label is already using the width. In
    /// words, because the row it belongs to is greyed and a colour is never the only thing
    /// the dashboard says anything with.
    pub(crate) fn short(self) -> &'static str {
        match self {
            Self::NotRunning => "not running",
            Self::AlreadyRunning => "already running",
            Self::Running => "running",
            Self::NoWorkspace => "no checkout recorded",
            Self::WorkspaceGone => "checkout gone",
            Self::NotAnEnvironment => "not a dev environment",
        }
    }
}

impl Action {
    /// Every action, in the order the menu lists them: what is done most often first, what
    /// cannot be undone last.
    pub(crate) const ALL: [Action; 7] = [
        Action::Stop,
        Action::Up,
        Action::Refresh,
        Action::Shell,
        Action::Code,
        Action::Atop,
        Action::Remove,
    ];

    /// The key that picks it out of the menu.
    pub(crate) fn key(self) -> char {
        match self {
            Self::Stop => 's',
            Self::Up => 'u',
            Self::Refresh => 'r',
            Self::Shell => 'h',
            Self::Code => 'c',
            Self::Atop => 'a',
            Self::Remove => 'd',
        }
    }

    /// How the menu names it.
    ///
    /// `refresh` says that it rebuilds, because the nearest thing `vk dev` has to the
    /// restart a reader expects is a command that builds the image again first and can take
    /// minutes over it.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Up => "start",
            Self::Refresh => "refresh (rebuilds)",
            Self::Shell => "shell into it",
            Self::Code => "open the editor",
            Self::Atop => "the guest's own usage panel",
            Self::Remove => "remove it",
        }
    }

    /// What it does, in the words a reader needs in order to decide.
    pub(crate) fn about(self) -> &'static str {
        match self {
            Self::Stop => "the VM goes down; start brings it back",
            Self::Up => "boots it, which takes a moment",
            Self::Refresh => "builds the image again and restarts it, which can take minutes",
            Self::Shell => "hands this terminal over until the shell exits",
            Self::Code => "opens VS Code on it, booting it first if it is down",
            Self::Atop => "hands this terminal to vk atop: what the guest sees inside itself",
            Self::Remove => "deletes the state directory and everything in it",
        }
    }

    pub(crate) fn weight(self) -> Weight {
        match self {
            Self::Atop => Weight::ReadOnly,
            Self::Stop | Self::Up | Self::Refresh | Self::Shell | Self::Code => Weight::Reversible,
            Self::Remove => Weight::Destructive,
        }
    }

    /// Whether this one takes the terminal over rather than running out of sight.
    pub(crate) fn takes_the_terminal(self) -> bool {
        matches!(self, Self::Shell | Self::Code | Self::Atop)
    }

    /// The `vk dev` verb it re-execs.
    fn verb(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Up => "up",
            Self::Refresh => "refresh",
            Self::Shell => "shell",
            Self::Code => "code",
            Self::Atop => "atop",
            Self::Remove => "gc",
        }
    }

    /// What this action would run for this environment, or why it cannot be offered.
    pub(crate) fn job(self, env: &Env) -> Result<Job, Refusal> {
        let argv = match self {
            // The state directory selects the VM, as it does for every other command that
            // takes a directory, and the panel needs nothing from the checkout.
            Self::Atop => {
                if !env.is_running() {
                    return Err(Refusal::NotRunning);
                }
                vec![
                    OsString::from(self.verb()),
                    env.dir.clone().into_os_string(),
                    OsString::from("--follow"),
                ]
            }
            // `gc` is host-wide and addressed by the state directory's own name, so it is
            // the one thing still available for an environment whose checkout is gone —
            // which is exactly what it is there to clear up.
            Self::Remove => {
                let row = env.row.as_ref().ok_or(Refusal::NotAnEnvironment)?;
                if env.is_running() {
                    return Err(Refusal::Running);
                }
                vec![
                    OsString::from("dev"),
                    OsString::from(self.verb()),
                    OsString::from("--yes"),
                    OsString::from(&row.name),
                ]
            }
            // By the state directory's name, as `vk dev list` gives it: a named stop is
            // host state only, so it stops a VM whose checkout is gone, or whose config
            // no longer reads, as well as any other — and that name is the identity whole.
            Self::Stop => {
                let row = env.row.as_ref().ok_or(Refusal::NotAnEnvironment)?;
                if !env.is_running() {
                    return Err(Refusal::NotRunning);
                }
                vec![
                    OsString::from("dev"),
                    OsString::from(self.verb()),
                    OsString::from(&row.name),
                ]
            }
            Self::Up | Self::Refresh | Self::Shell | Self::Code => {
                let row = env.row.as_ref().ok_or(Refusal::NotAnEnvironment)?;
                let workspace = row.workspace.as_deref().ok_or(Refusal::NoWorkspace)?;
                if row.flags.contains(&Flag::WorkspaceMissing) {
                    return Err(Refusal::WorkspaceGone);
                }
                if self == Self::Up && env.is_running() {
                    return Err(Refusal::AlreadyRunning);
                }
                // Both fields come out of one record — the plan the environment booted
                // with, which carries them side by side — so a row with a checkout has a
                // name for its environment too, and `dev` is what `vk dev` itself defaults
                // to for the one that predates the field.
                let environment = row.environment.as_deref().unwrap_or("dev");
                let mut argv = vec![
                    OsString::from("dev"),
                    OsString::from("--workspace"),
                    workspace.as_os_str().to_os_string(),
                    OsString::from("--environment"),
                    OsString::from(environment),
                ];
                // The config it booted from, where it recorded one: the state directory is
                // the workspace's and the name's alone, so a boot from the workspace's
                // default config would be this same environment built from another one.
                if let Some(config) = &row.config {
                    argv.push(OsString::from("--dev-config"));
                    argv.push(config.as_os_str().to_os_string());
                }
                argv.push(OsString::from(self.verb()));
                argv
            }
        };
        Ok(Job {
            action: self,
            name: env.name().to_string(),
            argv,
        })
    }
}

/// An action that has been decided on: which one, on what, and the command line it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Job {
    pub(crate) action: Action,
    /// the environment's name, for the key bar to say what it did
    pub(crate) name: String,
    /// everything after the binary
    pub(crate) argv: Vec<OsString>,
}

impl Job {
    /// What the command reads as, so a reader agreeing to something destructive is agreeing
    /// to a command they can read rather than to a word in a menu.
    ///
    /// Written `vk`, which is the name of the thing rather than the path this process was
    /// started from: a reader who wants to run it again types `vk`.
    pub(crate) fn line(&self) -> String {
        let mut out = String::from("vk");
        for arg in &self.argv {
            out.push(' ');
            out.push_str(&arg.to_string_lossy());
        }
        out
    }

    /// The command itself, pointed at the binary this dashboard is part of.
    pub(crate) fn command(&self) -> Result<Command> {
        let exe = std::env::current_exe().context("finding the vk this dashboard is part of")?;
        let mut command = Command::new(exe);
        command.args(&self.argv);
        Ok(command)
    }
}

/// Run a quiet action on a thread and refresh the environment list when it finishes,
/// so changes appear immediately rather than waiting for the refresh interval.
pub(crate) fn spawn(job: Job, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let said = run(&job);
        if tx.send(Event::Said(said)).is_err() {
            return; // the dashboard is gone
        }
        poll::refresh_once(tx);
    });
}

/// Run one, with its output kept off the screen the dashboard is drawing on.
fn run(job: &Job) -> String {
    let (label, name) = (job.action.label(), job.name.as_str());
    let mut command = match job.command() {
        Ok(command) => command,
        Err(report) => return format!("{label}: {name}: {report:#}"),
    };
    // Captured rather than inherited: a child writing to this terminal would write over the
    // frame. Nothing is read from stdin either — a command that wanted to ask something
    // would otherwise sit there unseen, waiting for an answer nobody can give it.
    command.stdin(Stdio::null());
    // A process group of its own, out of the terminal's reach: a Ctrl-C typed into a shell
    // the dashboard has handed the terminal to meanwhile is that shell's, and must not
    // end a rebuild running out of sight.
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    match command.output() {
        Err(report) => format!("{label}: {name}: {report}"),
        Ok(done) if done.status.success() => format!("{label}: {name} finished"),
        Ok(done) => match complaint(&done.stderr) {
            Some(said) => format!("{label}: {name}: {said}"),
            None => format!("{label}: {name}: exited with {}", done.status),
        },
    }
}

/// The last thing a failed child complained about, for the one line the key bar has.
///
/// Lossy on purpose: this is a diagnostic on its way to a terminal, not a path or a stream,
/// and the painter gives a cell to nothing the terminal would act on.
fn complaint(stderr: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stderr);
    let last = text.lines().rev().find(|line| !line.trim().is_empty())?;
    Some(last.trim().to_string())
}

#[cfg(test)]
mod tests {
    // An assertion is how a test reports; the panic lints this module gates on exist to
    // keep a live terminal intact, which no test has.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::dash::envs::fixture::{row, vm};
    use crate::dash::envs::join;
    use crate::dev::list::Status;

    /// A running environment with a checkout behind it.
    fn running() -> Env {
        join(
            vec![row("virtkit-4171942f2d70bae7", "/state/a", Status::Running)],
            vec![vm("/state/a", 3928432)],
        )
        .remove(0)
    }

    fn stopped() -> Env {
        join(
            vec![row("wab-3ce70a9544f1e8b2", "/state/wab", Status::Stopped)],
            Vec::new(),
        )
        .remove(0)
    }

    /// The same environment, with the checkout it recorded gone from this host.
    fn orphaned() -> Env {
        let mut stale = row("wab-3ce70a9544f1e8b2", "/state/wab", Status::Stopped);
        stale.flags.push(Flag::WorkspaceMissing);
        join(vec![stale], Vec::new()).remove(0)
    }

    /// The arguments of an action that can be offered, as strings.
    fn argv(action: Action, env: &Env) -> Vec<String> {
        action
            .job(env)
            .unwrap_or_else(|refusal| panic!("{:?}: {}", action, refusal.why()))
            .argv
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    /// Every action has a key of its own: a menu with two actions on one letter is a menu
    /// that does the wrong one.
    #[test]
    fn no_two_actions_share_a_key() {
        let mut keys: Vec<char> = Action::ALL.iter().map(|action| action.key()).collect();
        keys.sort_unstable();
        let offered = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), offered, "two actions answer to the same key");
        assert_eq!(offered, Action::ALL.len());
    }

    /// An action names the environment's own checkout, its own environment name and the
    /// config it booted from, and none of them comes from the directory the dashboard was
    /// started in: `vk dev` resolves a workspace from the working directory, two
    /// environments over one checkout differ only in the name, and one booted from another
    /// config would be rebuilt from the default — so a command given less acts on something
    /// else. A stop names the state directory, which is all three at once.
    #[test]
    fn an_action_names_the_environment_it_acts_on_and_not_the_working_directory() {
        let env = running();
        assert_eq!(
            argv(Action::Refresh, &env),
            [
                "dev",
                "--workspace",
                "/home/reader/src/virtkit",
                "--environment",
                "dev",
                "--dev-config",
                "/home/reader/src/virtkit/.virtkit/config.toml",
                "refresh"
            ]
        );
        assert_eq!(
            argv(Action::Stop, &env),
            ["dev", "stop", "virtkit-4171942f2d70bae7"]
        );
        assert_eq!(argv(Action::Shell, &env).last().unwrap(), "shell");
        assert_eq!(argv(Action::Code, &env).last().unwrap(), "code");
        assert_eq!(argv(Action::Refresh, &env).last().unwrap(), "refresh");
        assert_eq!(argv(Action::Up, &stopped()).last().unwrap(), "up");

        let cwd = std::env::current_dir().unwrap().display().to_string();
        assert!(
            !argv(Action::Refresh, &env).contains(&cwd),
            "the action ran wherever the dashboard was opened"
        );

        // The panel is pointed at the state directory, which is what selects a running VM
        // for every other command that takes a directory.
        assert_eq!(argv(Action::Atop, &env), ["atop", "/state/a", "--follow"]);
    }

    /// `gc` is host-wide and addressed by the state directory's name, so it takes no
    /// workspace — and is written out with `--yes`, since the dashboard has already asked.
    #[test]
    fn removing_an_environment_names_it_and_no_workspace() {
        let env = stopped();
        let argv = argv(Action::Remove, &env);
        assert_eq!(argv, ["dev", "gc", "--yes", "wab-3ce70a9544f1e8b2"]);
        assert!(!argv.iter().any(|arg| arg == "--workspace"), "{argv:?}");
    }

    /// The binary is the one this dashboard is part of, never whatever `vk` a `PATH` finds:
    /// a reader running a development build expects it to drive that build.
    #[test]
    fn an_action_runs_this_binary_and_not_one_off_the_path() {
        let job = Action::Stop.job(&running()).unwrap();
        let program = std::env::current_exe().unwrap();
        assert_eq!(job.command().unwrap().get_program(), program.as_os_str());
        assert_ne!(program.as_os_str(), "vk");
        assert!(program.is_absolute(), "{}", program.display());
        // And the line a reader is shown names the command rather than this path.
        assert!(job.line().starts_with("vk dev "), "{}", job.line());
    }

    /// What is already down cannot be stopped, and what is already up cannot be started.
    /// The menu greys these out rather than letting `vk` explain it after the fact.
    #[test]
    fn an_action_that_makes_no_sense_for_the_state_is_refused() {
        let (up, down) = (running(), stopped());
        assert_eq!(Action::Up.job(&up).err(), Some(Refusal::AlreadyRunning));
        assert_eq!(Action::Stop.job(&down).err(), Some(Refusal::NotRunning));
        assert_eq!(Action::Atop.job(&down).err(), Some(Refusal::NotRunning));
        assert_eq!(Action::Remove.job(&up).err(), Some(Refusal::Running));
        assert!(Action::Stop.job(&up).is_ok());
        assert!(Action::Up.job(&down).is_ok());
        // Both of these boot what is down, so neither is refused for being down.
        assert!(Action::Shell.job(&down).is_ok());
        assert!(Action::Code.job(&down).is_ok());
    }

    /// A bare `vk run` is not a dev environment, so every `vk dev` action is refused for it
    /// — and the one panel that reads the VM itself is not.
    #[test]
    fn a_vm_with_no_environment_behind_it_has_only_the_panel() {
        let bare = join(Vec::new(), vec![vm("/state/scratch", 4242)]).remove(0);
        assert!(bare.is_running());
        for action in [Action::Stop, Action::Refresh, Action::Shell, Action::Remove] {
            assert_eq!(
                action.job(&bare).err(),
                Some(Refusal::NotAnEnvironment),
                "{action:?}"
            );
        }
        assert!(Action::Atop.job(&bare).is_ok());
    }

    /// An environment whose checkout is gone from the host cannot be run in — and removing
    /// what it left behind is exactly what is still worth doing to it, so `gc` stays.
    #[test]
    fn gc_stays_available_for_an_environment_whose_checkout_is_gone() {
        let env = orphaned();
        for action in [Action::Up, Action::Refresh, Action::Code] {
            assert_eq!(
                action.job(&env).err(),
                Some(Refusal::WorkspaceGone),
                "{action:?}"
            );
        }
        assert!(Action::Remove.job(&env).is_ok());
        assert!(
            Refusal::WorkspaceGone.why().contains('d'),
            "the reason does not name the key that is still offered"
        );

        // Still running, it can be stopped all the same — by name, which needs no checkout
        // — or `d` would be refused as running and nothing at all would be offered.
        let mut stale = row("wab-3ce70a9544f1e8b2", "/state/wab", Status::Running);
        stale.flags.push(Flag::WorkspaceMissing);
        let env = join(vec![stale], vec![vm("/state/wab", 4242)]).remove(0);
        assert_eq!(
            argv(Action::Stop, &env),
            ["dev", "stop", "wab-3ce70a9544f1e8b2"]
        );

        // And one that recorded no checkout at all is refused for a different reason, with
        // `gc` offered for the same one.
        let mut nameless = row("virtkit-9c02b118", "/state/c", Status::NeverBooted);
        nameless.workspace = None;
        let env = join(vec![nameless], Vec::new()).remove(0);
        assert_eq!(Action::Up.job(&env).err(), Some(Refusal::NoWorkspace));
        assert!(Action::Remove.job(&env).is_ok());
    }

    /// One action destroys something, and it is the one that asks. The panel changes
    /// nothing at all, which is why it is offered for a VM nothing else is.
    #[test]
    fn what_cannot_be_undone_is_what_asks_first() {
        let destructive: Vec<&str> = Action::ALL
            .iter()
            .filter(|action| action.weight() == Weight::Destructive)
            .map(|action| action.label())
            .collect();
        assert_eq!(destructive, ["remove it"]);
        assert_eq!(Action::Atop.weight(), Weight::ReadOnly);
        // The three that hand the terminal over are the three that are interactive.
        let taking: Vec<char> = Action::ALL
            .iter()
            .filter(|action| action.takes_the_terminal())
            .map(|action| action.key())
            .collect();
        assert_eq!(taking, ['h', 'c', 'a']);
    }

    /// A child that failed says why in the one line the key bar has, rather than leaving
    /// the reader with an exit status.
    #[test]
    fn a_failure_is_reported_in_the_childs_own_words() {
        assert_eq!(
            complaint(b"building\nvirtkit: no config in /srv/gone\n\n").as_deref(),
            Some("virtkit: no config in /srv/gone")
        );
        assert_eq!(complaint(b""), None);
        assert_eq!(complaint(b"   \n\n"), None);
    }
}
