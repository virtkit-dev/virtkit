//! The two listings, joined into the one thing the dashboard is about: an environment.
//!
//! [`crate::dev::list::state`] knows every environment this host keeps state for, running
//! or not, but nothing about the VM behind a running one. [`crate::vms::running`] knows
//! every live VM, including ones that answer to no environment at all. Joined, they say
//! what is on this host and what it is doing.
//!
//! Join by canonical state directory, not path spelling. A symlinked `$XDG_STATE_HOME` or
//! an automounted home can give one directory two names; comparing them would produce a
//! stopped environment row and a nameless VM row. Both sides use [`crate::vms::canonical`].
//!
//! Keep unmatched VMs too: a bare `vk run --state-dir` still gets its own row.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dev::list::{Row, Status};
use crate::vms::{VmEntry, canonical};

/// One environment: what the environment listing says about it, and what the VM listing
/// says about the VM behind it, when there is one. At least one of the two is always
/// present — a row with neither would have no identity to have been built from.
#[derive(Debug, Clone)]
pub(crate) struct Env {
    /// The state directory, canonicalized: this row's identity, and what every command the
    /// dashboard runs for it is pointed at.
    pub(crate) dir: PathBuf,
    /// The environment, when the join found one. `None` for a bare `vk run`.
    pub(crate) row: Option<Row>,
    /// The live VM, when it is up. `None` for an environment that is down.
    pub(crate) vm: Option<VmEntry>,
    /// What this environment's whole process tree holds on the host now. Only a running VM
    /// costs anything, so a stopped environment reports nothing rather than zero: the
    /// difference between idle and not there is the one the list is about.
    pub(crate) mem_used: Option<u64>,
}

impl Env {
    /// What to call this row: the environment's name, or failing that the state directory's
    /// own last component.
    ///
    /// Not the VM's label, which is the configuration it was built from — a live one reads
    /// `.devcontainer/Dockerfile` — so it names an image and not a machine.
    pub(crate) fn name(&self) -> &str {
        if let Some(row) = &self.row {
            return &row.name;
        }
        self.dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?")
    }

    /// Whether there is a live VM behind this row.
    pub(crate) fn is_running(&self) -> bool {
        self.vm.is_some()
    }

    /// The state, as one word.
    ///
    /// What is running decides it, not the environment's recorded status: the two listings
    /// are read one after the other, and where they disagree it is because a boot finished
    /// or a VM went away in between. What is running is the truer of the two.
    pub(crate) fn state(&self) -> &'static str {
        if self.is_running() {
            return "running";
        }
        match self.row.as_ref().map(|row| row.status) {
            Some(Status::NeverBooted) => "never-booted",
            _ => "stopped",
        }
    }

    /// The checkout this environment belongs to.
    pub(crate) fn workspace(&self) -> Option<&Path> {
        self.vm
            .as_ref()
            .and_then(|vm| vm.project_dir.as_deref())
            .or_else(|| self.row.as_ref().and_then(|row| row.workspace.as_deref()))
    }

    /// How long the VM behind this row has been up. The registry records the moment it
    /// started, so this is measured against the clock rather than believed as a duration.
    pub(crate) fn uptime_secs(&self) -> Option<u64> {
        let started = self.vm.as_ref()?.created_secs;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        Some(now.saturating_sub(started))
    }

    /// The memory size the VM booted with, the `--mem` token verbatim. Both listings record
    /// it, so a stopped environment has a ceiling to show even with no VM behind it.
    pub(crate) fn mem_configured(&self) -> Option<&str> {
        self.vm
            .as_ref()
            .and_then(|vm| vm.mem.as_deref())
            .or_else(|| self.row.as_ref().and_then(|row| row.mem.as_deref()))
    }

    /// Sort key: what is running first, then by name, then by directory — so two
    /// environments sharing a name hold a stable order between refreshes rather than
    /// swapping places under the selection.
    fn order(&self) -> (bool, &str, &Path) {
        (!self.is_running(), self.name(), self.dir.as_path())
    }
}

/// Join the two listings into the rows the dashboard shows, running first.
pub(crate) fn join(rows: Vec<Row>, vms: Vec<VmEntry>) -> Vec<Env> {
    let mut live: HashMap<PathBuf, VmEntry> = vms
        .into_iter()
        .map(|vm| (canonical(&vm.state_dir), vm))
        .collect();

    let mut envs: Vec<Env> = rows
        .into_iter()
        .map(|row| {
            let dir = canonical(&row.dir);
            let vm = live.remove(&dir);
            Env {
                dir,
                mem_used: row.mem_used_bytes,
                row: Some(row),
                vm,
            }
        })
        .collect();

    // Whatever is left is running under no environment this host keeps state for.
    envs.extend(live.into_values().map(|vm| Env {
        dir: canonical(&vm.state_dir),
        row: None,
        vm: Some(vm),
        mem_used: None,
    }));

    envs.sort_by(|left, right| left.order().cmp(&right.order()));
    envs
}

/// Listings built by hand, for the tests here and in the modules that read these rows.
/// Both structs are the listings' own and every field of them is public, so a fixture is a
/// literal rather than a constructor either listing would have to grow for a test's sake.
#[cfg(test)]
pub(crate) mod fixture {
    use super::{Row, Status, VmEntry};
    use std::path::PathBuf;

    /// One environment, as the listing reports it.
    pub(crate) fn row(name: &str, dir: &str, status: Status) -> Row {
        Row {
            name: name.to_string(),
            dir: PathBuf::from(dir),
            workspace: Some(PathBuf::from("/home/reader/src/virtkit")),
            environment: Some("dev".to_string()),
            config: Some(PathBuf::from("/home/reader/src/virtkit/.virtkit/config.toml")),
            status,
            created_by: None,
            booted_secs: None,
            age_secs: Some(600),
            mem_used_bytes: None,
            mem: Some("8G".to_string()),
            size_bytes: None,
            flags: Vec::new(),
        }
    }

    /// A live VM, as the registry records one.
    pub(crate) fn vm(dir: &str, pid: u32) -> VmEntry {
        VmEntry {
            state_dir: PathBuf::from(dir),
            project_dir: Some(PathBuf::from("/home/reader/src/virtkit")),
            pid,
            label: ".devcontainer/Dockerfile".to_string(),
            exec_addr: format!("vsock-auto://{dir}/vsock.sock:4444"),
            ssh_addr: None,
            atop_log: None,
            created_secs: 0,
            vmm: Some("libkrun".to_string()),
            vmm_pid: Some(pid.saturating_add(1)),
            cpus: Some(22),
            mem: Some("8G".to_string()),
            nested: Some(true),
            guest_ip: Some(std::net::Ipv4Addr::new(192, 168, 127, 2)),
            stale_recipe: None,
            services: Vec::new(),
        }
    }
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

    use super::fixture::{row, vm};
    use super::*;

    /// An environment that is down has no VM to read, and says so by having none rather
    /// than by carrying an empty one every pane would have to interrogate.
    #[test]
    fn a_stopped_environment_joins_to_no_vm() {
        let envs = join(
            vec![row("wab-3ce70a9544f1e8b2", "/state/wab", Status::Stopped)],
            Vec::new(),
        );
        assert_eq!(envs.len(), 1);
        assert!(envs[0].vm.is_none());
        assert!(!envs[0].is_running());
        assert_eq!(envs[0].state(), "stopped");
        assert_eq!(envs[0].uptime_secs(), None);
        assert_eq!(envs[0].mem_used, None);
        // It still has a ceiling: a stopped environment recorded one, and a ceiling with
        // no cost against it is the point.
        assert_eq!(envs[0].mem_configured(), Some("8G"));
    }

    /// A bare `vk run` is not a dev environment and is still something running on this
    /// machine, so it gets a row — named after its state directory, since it has no
    /// environment to be named by and a VM's label names an image, not a machine.
    #[test]
    fn a_vm_with_no_environment_still_gets_a_row() {
        let envs = join(Vec::new(), vec![vm("/state/scratch-2ab41c70", 4242)]);
        assert_eq!(envs.len(), 1);
        assert!(envs[0].row.is_none());
        assert!(envs[0].is_running());
        assert_eq!(envs[0].name(), "scratch-2ab41c70");
        assert_eq!(envs[0].state(), "running");
    }

    /// Two environments over one checkout differ only in their state directory, and the
    /// join keeps them apart by it rather than folding them into one row.
    #[test]
    fn two_environments_over_one_checkout_stay_two_rows() {
        let envs = join(
            vec![
                row("virtkit-4171942f2d70bae7", "/state/a", Status::Running),
                row("virtkit-9c02b11840e6c3da", "/state/b", Status::Running),
            ],
            vec![vm("/state/a", 11), vm("/state/b", 12)],
        );
        assert_eq!(envs.len(), 2);
        assert_ne!(envs[0].dir, envs[1].dir);
        assert_ne!(envs[0].name(), envs[1].name());
        assert!(envs.iter().all(Env::is_running));
        assert_eq!(envs[0].vm.as_ref().unwrap().pid, 11);
    }

    /// What is running is listed first, because it is what the reader came to look at, and
    /// the order is stable between refreshes so the selection does not wander.
    #[test]
    fn running_environments_sort_before_stopped_ones() {
        let envs = join(
            vec![
                row("aaa-0000000000000000", "/state/aaa", Status::Stopped),
                row("zzz-1111111111111111", "/state/zzz", Status::Running),
                row("mmm-2222222222222222", "/state/mmm", Status::NeverBooted),
            ],
            vec![vm("/state/zzz", 9)],
        );
        let names: Vec<&str> = envs.iter().map(Env::name).collect();
        assert_eq!(
            names,
            [
                "zzz-1111111111111111",
                "aaa-0000000000000000",
                "mmm-2222222222222222"
            ]
        );
        assert_eq!(envs[2].state(), "never-booted");
    }

    /// The two listings are read one after the other, so they can disagree. A VM that came
    /// up in between is running, whatever the older of the two believed — and one that went
    /// away in between is not, whatever its environment still records.
    #[test]
    fn what_is_running_decides_the_state_word() {
        let appeared = join(
            vec![row("wab", "/state/wab", Status::Stopped)],
            vec![vm("/state/wab", 4242)],
        );
        assert_eq!(appeared.len(), 1, "the join split one environment in two");
        assert!(appeared[0].is_running());
        assert_eq!(appeared[0].state(), "running");

        let gone = join(vec![row("wab", "/state/wab", Status::Running)], Vec::new());
        assert_eq!(gone[0].state(), "stopped");
    }
}
