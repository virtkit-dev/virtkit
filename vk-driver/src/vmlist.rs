//! VM inventory rows for running primaries, stopped named runs, dev state directories
//! and their compose services. Each primary precedes its services within the project.
//!
//! [`rows_with`] takes the service boot check as an argument, so tests can build rows
//! without reading the filesystem. [`rows`] checks for each service's console log.

use std::path::{Path, PathBuf};

use serde::Serialize;
use vk_core::fleetctl::UnitStatus;

use crate::vms::{Freshness, Published, VmEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// a `vk dev` environment
    Dev,
    /// a `vk run`
    Run,
    /// a compose service of either
    Service,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Dev => "dev",
            Kind::Run => "run",
            Kind::Service => "service",
        }
    }
}

pub const RUNNING: &str = "running";

pub const STOPPED: &str = "stopped";

/// Dev state with no recorded boot, including an interrupted first boot or a throwaway task.
pub const NEVER_BOOTED: &str = "never booted";

/// Whether a row's status is at rest: stopped, or state that never booted.
fn at_rest(status: &str) -> bool {
    status == STOPPED || status == NEVER_BOOTED
}

/// One `vk list` row; `vk list --json` is an array of these.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Row {
    /// The primary's name or pid, or `NAME/SERVICE` for commands that accept service references.
    pub name: String,
    pub kind: Kind,
    /// The reported state, `never booted` for dev state without a recorded boot, or `-` for
    /// a service with unknown state. A primary can be `starting` during pull, build or boot.
    /// An overdue stop keeps the status `stopping`, with the reason in `attention`.
    pub status: String,
    /// the VM a compose service belongs to; `null` for a primary
    pub parent: Option<String>,
    /// The primary's state directory. A service and its primary share this path even
    /// when another primary has the same display name.
    #[serde(skip)]
    pub primary_dir: PathBuf,
    /// the managing `vk run`'s pid, while it runs
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    /// what the VM's process tree holds on the host now, services included
    pub mem_used_bytes: Option<u64>,
    /// the memory size it booted with
    pub mem: Option<String>,
    /// what it boots: the image, the compose primary or the Dockerfile
    pub image: Option<String>,
    /// The dev workspace or run project directory.
    #[serde(with = "crate::names::opt_os_string")]
    pub project: Option<PathBuf>,
    /// The dev environment name, also present on its service rows.
    pub environment: Option<String>,
    #[serde(with = "crate::names::os_string")]
    pub state_dir: PathBuf,
    pub exec_addr: Option<String>,
    pub ssh_addr: Option<String>,
    /// its address on the run's LAN
    pub ip: Option<String>,
    /// the ports published to the host, `listen->to`
    pub published: Vec<String>,
    /// With `--stale`, whether any image in a running primary's workload would be rebuilt.
    /// Unknown results, services and stopped VMs have a JSON value of `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<Option<bool>>,
    /// row derived from a stale registration or transient record, or a booted dev environment
    /// without an indexed name. Omitted from plain JSON when false
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale_record: bool,
    /// Reason and recovery commands for an overdue stop on a live run. Omitted from full
    /// JSON rows when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attention: Option<String>,
}

/// Append `!` for attention and `*` for stale records. JSON keeps both flags separate from status.
fn status_cell(r: &Row) -> String {
    let mut cell = r.status.clone();
    if r.attention.is_some() {
        cell.push('!');
    }
    if r.stale_record {
        cell.push('*');
    }
    cell
}

/// Whether a VM with this status is on its way up or down: `--running` keeps it.
fn on_its_way(status: &str) -> bool {
    use crate::vmstate::State;
    status == State::Starting.label() || status == State::Stopping.label()
}

/// A running primary and its current measurements.
pub struct Live<'a> {
    pub entry: &'a VmEntry,
    pub name: Option<String>,
    pub kind: Kind,
    pub environment: Option<String>,
    /// its services' states; `None` when the VM could not be asked
    pub units: Option<Vec<UnitStatus>>,
    pub published: Vec<Published>,
    pub mem_used: Option<u64>,
    /// with `--stale`, its freshness
    pub fresh: Option<Freshness>,
    /// A recorded stop, active or overdue, overrides the normal `running` status.
    pub transient: Option<&'static str>,
    /// what needs attention about it (see [`Row::attention`])
    pub attention: Option<String>,
    /// whether the row uses stale records (see [`Row::stale_record`])
    pub stale_record: bool,
}

/// A primary without a live registry entry, identified by its indexed name or dev directory name.
pub struct Known {
    pub name: String,
    pub dir: PathBuf,
    pub kind: Kind,
    /// [`STOPPED`], [`NEVER_BOOTED`], or the recorded `starting` or `stopping` state
    pub status: &'static str,
    /// what needs attention about it (see [`Row::attention`])
    pub attention: Option<String>,
    /// whether the row uses stale records (see [`Row::stale_record`])
    pub stale_record: bool,
    /// the registry entry it last ran with, if it left one
    pub last: Option<VmEntry>,
    /// its project, as listed and as a directory REF matches it
    pub project: Option<PathBuf>,
    pub environment: Option<String>,
}

/// Sort by project path (missing last), then by primary kind (dev first) and name.
/// Each primary precedes its services in name order.
pub fn rows(live: &[Live], known: &[Known], now: u64) -> Vec<Row> {
    rows_with(live, known, now, booted)
}

/// [`crate::units::boot_unit`] gives the VMM its console log path. The log records a
/// start. The directory alone is insufficient because provisioning creates it first.
pub(crate) fn booted(svc_dir: &Path) -> bool {
    svc_dir.join(crate::run::CONSOLE_LOG).exists()
}

/// Build the rows using the supplied service boot check. A service qualifies when its
/// manager reports a state other than `stopped` or a console log records an earlier start.
/// A declaration alone, including a profiled-out or on-demand service, is insufficient.
/// `vk start VM/SERVICE` still starts a service without a row.
pub fn rows_with(
    live: &[Live],
    known: &[Known],
    now: u64,
    booted: impl Fn(&Path) -> bool,
) -> Vec<Row> {
    let mut out: Vec<Row> = Vec::new();
    for l in live {
        let e = l.entry;
        let name = l.name.clone().unwrap_or_else(|| e.pid.to_string());
        let status = l.transient.unwrap_or(RUNNING);
        let (own, by_service): (Vec<&Published>, Vec<&Published>) =
            l.published.iter().partition(|(p, _)| p.service.is_none());
        out.push(Row {
            name: name.clone(),
            kind: l.kind,
            status: status.into(),
            parent: None,
            primary_dir: e.state_dir.clone(),
            pid: Some(e.pid),
            uptime_secs: Some(now.saturating_sub(e.created_secs)),
            mem_used_bytes: l.mem_used,
            mem: e.mem.clone(),
            image: Some(e.label.clone()),
            project: e.project_dir.clone(),
            environment: l.environment.clone(),
            state_dir: e.state_dir.clone(),
            exec_addr: Some(e.exec_addr.clone()),
            ssh_addr: e.ssh_addr.clone(),
            ip: e.guest_ip.map(|ip| ip.to_string()),
            published: own.into_iter().map(published_text).collect(),
            stale: l.fresh.map(Freshness::json),
            attention: l.attention.clone(),
            stale_record: l.stale_record,
        });
        for s in &e.services {
            let unit = l
                .units
                .as_ref()
                .and_then(|u| u.iter().find(|u| u.name == s.name));
            let dir = service_dir(&s.exec_addr)
                .unwrap_or_else(|| e.state_dir.join(format!("svc-{}", s.name)));
            if !unit.is_some_and(|u| u.state != STOPPED) && !booted(&dir) {
                continue;
            }
            // Its VMM, as its manager reports it; one that predates that reports none.
            let pid = unit.and_then(|u| u.pid);
            let ours = pid.and_then(|p| i32::try_from(p).ok());
            out.push(Row {
                name: format!("{name}/{}", s.name),
                kind: Kind::Service,
                status: unit.map_or_else(|| "-".into(), |u| u.state.clone()),
                parent: Some(name.clone()),
                primary_dir: e.state_dir.clone(),
                pid,
                uptime_secs: ours
                    .and_then(crate::usage::proc_age)
                    .map(|age| age.as_secs()),
                mem_used_bytes: ours.and_then(crate::usage::tree_resident),
                mem: unit.and_then(|u| u.mem.clone()),
                image: unit.and_then(|u| u.image.clone()),
                project: e.project_dir.clone(),
                environment: l.environment.clone(),
                state_dir: dir,
                exec_addr: Some(s.exec_addr.clone()),
                ssh_addr: None,
                ip: unit.map(|u| crate::vms::bare_ip(&u.ip).to_string()),
                published: by_service
                    .iter()
                    .filter(|(p, _)| p.service.as_deref() == Some(s.name.as_str()))
                    .map(|p| published_text(p))
                    .collect(),
                stale: None,
                stale_record: false,
                attention: None,
            });
        }
    }
    for k in known {
        let last = k.last.as_ref();
        out.push(Row {
            name: k.name.clone(),
            kind: k.kind,
            status: k.status.into(),
            parent: None,
            primary_dir: k.dir.clone(),
            pid: None,
            uptime_secs: None,
            mem_used_bytes: None,
            mem: last.and_then(|e| e.mem.clone()),
            image: last.map(|e| e.label.clone()),
            project: k.project.clone(),
            environment: k.environment.clone(),
            state_dir: k.dir.clone(),
            exec_addr: None,
            ssh_addr: None,
            ip: None,
            published: Vec::new(),
            stale: None,
            attention: k.attention.clone(),
            stale_record: k.stale_record,
        });
        for s in last.map(|e| e.services.as_slice()).unwrap_or_default() {
            let dir = k.dir.join(format!("svc-{}", s.name));
            if !booted(&dir) {
                continue;
            }
            out.push(Row {
                name: format!("{}/{}", k.name, s.name),
                kind: Kind::Service,
                status: STOPPED.into(),
                parent: Some(k.name.clone()),
                primary_dir: k.dir.clone(),
                pid: None,
                uptime_secs: None,
                mem_used_bytes: None,
                mem: None,
                image: None,
                project: k.project.clone(),
                environment: k.environment.clone(),
                state_dir: dir,
                exec_addr: None,
                ssh_addr: None,
                ip: None,
                published: Vec::new(),
                stale: None,
                stale_record: false,
                attention: None,
            });
        }
    }
    let kind_of: std::collections::HashMap<String, Kind> = out
        .iter()
        .filter(|r| r.parent.is_none())
        .map(|r| (r.name.clone(), r.kind))
        .collect();
    out.sort_by_key(|r| sort_key(r, &kind_of));
    out
}

fn sort_key(
    r: &Row,
    kind_of: &std::collections::HashMap<String, Kind>,
) -> (bool, Option<PathBuf>, Kind, String, bool, String) {
    let primary = r.parent.clone().unwrap_or_else(|| r.name.clone());
    let kind = kind_of.get(&primary).copied().unwrap_or(r.kind);
    (
        r.project.is_none(),
        r.project.clone(),
        kind,
        primary,
        r.parent.is_some(),
        r.name.clone(),
    )
}

/// The service directory an exec address `vsock-auto://<svc-dir>/vsock.sock:4444` names.
fn service_dir(exec_addr: &str) -> Option<PathBuf> {
    let path = exec_addr.strip_prefix("vsock-auto://")?;
    let (sock, _port) = path.rsplit_once(':')?;
    Path::new(sock).parent().map(Path::to_path_buf)
}

fn published_text((e, liveness): &Published) -> String {
    let mut cell = crate::vms::published_addr(e);
    if liveness.unconfirmed() {
        cell.push_str(" (unconfirmed)");
    }
    cell
}

/// A state `vk list --state` keeps: a row's STATUS, as `--json` words it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum State {
    /// up
    Running,
    /// booted before, nothing up now
    Stopped,
    /// a dev environment's state that recorded no boot
    NeverBooted,
    /// its run holds it, no VM up yet
    Starting,
    /// asked to stop, not gone yet
    Stopping,
}

impl State {
    /// The row status this state is.
    fn status(self) -> &'static str {
        match self {
            State::Running => "running",
            State::Stopped => STOPPED,
            State::NeverBooted => NEVER_BOOTED,
            State::Starting => crate::vmstate::State::Starting.label(),
            State::Stopping => crate::vmstate::State::Stopping.label(),
        }
    }

    /// What `--running` stands for.
    pub const RUNNING: &[State] = &[State::Running];
    /// What `--stopped` stands for: every state with no VM up or on its way.
    pub const STOPPED: &[State] = &[State::Stopped, State::NeverBooted];
    /// What `--active` stands for: every state with a live process holding what it uses.
    pub const ACTIVE: &[State] = &[State::Running, State::Starting, State::Stopping];
}

/// One word naming VMs to list: a name or a glob, a directory, or a pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Word {
    /// a VM's name or a row's (`NAME/SERVICE`), or a glob over them
    Pattern(crate::namematch::Pattern),
    /// a VM's state dir or project directory (canonical), or with `below` any project under it
    Dir { dir: PathBuf, below: bool },
    /// a running VM's pid; with a service, that one of its services
    Pid(u32, Option<String>),
}

impl Word {
    /// Whether this word names the row `r`, whose VM's own row is `vm` (`r` itself for a VM).
    fn names(&self, r: &Row, vm: &Row) -> bool {
        match self {
            Word::Pattern(p) => p.matches(&r.name) || p.matches(&vm.name),
            Word::Dir { dir, below } => {
                crate::vms::canonical(&vm.state_dir) == *dir
                    || vm
                        .project
                        .as_deref()
                        .map(crate::vms::canonical)
                        .is_some_and(|p| p == *dir || (*below && p.starts_with(dir)))
            }
            Word::Pid(pid, service) => {
                vm.pid == Some(*pid)
                    && service.as_ref().is_none_or(|s| {
                        r.parent.is_some() && r.name.rsplit_once('/').is_some_and(|(_, n)| n == s)
                    })
            }
        }
    }
}

/// Which rows to keep. The words pick the VMs to look at, any of them; each other criterion
/// given narrows that down, a list of values keeping a row that matches any of them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Filter {
    /// only the rows these name, any of them (none: every row)
    pub words: Vec<Word>,
    /// only the rows in one of these states
    pub states: Vec<State>,
    pub kind: Option<Kind>,
    /// only the compose service of this name, of whichever VM the REF selected
    pub service: Option<String>,
    /// only rows with an attention message or stale records
    pub problems: bool,
    /// only the rows of compose services with one of these names
    pub services: Vec<String>,
    /// only the rows whose project is this directory (canonical) — or below it, with `below`
    pub workspace: Option<PathBuf>,
    pub below: bool,
}

impl Filter {
    /// Whether anything is asked for: a listing that keeps nothing says no VM matched,
    /// rather than that there is none.
    pub fn narrows(&self) -> bool {
        !self.words.is_empty()
            || !self.states.is_empty()
            || self.kind.is_some()
            || self.problems
            || !self.services.is_empty()
            || self.workspace.is_some()
    }

    /// The rows of `rows` this filter keeps, a service's judged with its VM's row.
    pub fn apply(&self, rows: Vec<Row>) -> Vec<Row> {
        let keep: Vec<bool> = rows
            .iter()
            .map(|r| {
                let vm = r
                    .parent
                    .as_ref()
                    .and_then(|p| rows.iter().find(|v| v.parent.is_none() && v.name == *p))
                    .unwrap_or(r);
                self.keeps(r, vm)
            })
            .collect();
        rows.into_iter()
            .zip(keep)
            .filter_map(|(r, k)| k.then_some(r))
            .collect()
    }

    fn keeps(&self, r: &Row, vm: &Row) -> bool {
        (self.words.is_empty() || self.words.iter().any(|w| w.names(r, vm)))
            && (self.states.is_empty() || self.states.iter().any(|s| s.status() == r.status))
            && self.kind.is_none_or(|k| k == r.kind)
            && self
                .service
                .as_ref()
                .is_none_or(|s| service_of(r) == Some(s.as_str()))
            && (!self.problems || r.attention.is_some() || r.stale_record)
            && (self.services.is_empty()
                || r.kind == Kind::Service
                    && r.name
                        .rsplit_once('/')
                        .is_some_and(|(_, s)| self.services.iter().any(|w| w == s)))
            && self.workspace.as_ref().is_none_or(|w| {
                r.project
                    .as_deref()
                    .map(crate::vms::canonical)
                    .is_some_and(|p| p == *w || (self.below && p.starts_with(w)))
            })
    }
}

/// The service component of a service row's name (`db` in `shop/db`); `None` for a primary.
fn service_of(r: &Row) -> Option<&str> {
    r.name.strip_prefix(r.parent.as_deref()?)?.strip_prefix('/')
}

/// Render the table. Only the narrow PROJECT column abbreviates `home` to `~`.
pub fn render(rows: &[Row], home: Option<&Path>, wide: bool, stale: bool) -> String {
    let dash = || "-".to_string();
    let mut headers = vec![
        "NAME", "KIND", "STATUS", "PID", "UPTIME", "MEM", "IMAGE", "PROJECT",
    ];
    if wide {
        headers.push("EXEC_ADDRESS");
    }
    headers.push("PUBLISHED");
    if stale {
        headers.push("STALE");
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let mut row = vec![
                r.name.clone(),
                r.kind.label().to_string(),
                status_cell(r),
                r.pid.map_or_else(dash, |p| p.to_string()),
                r.uptime_secs.map_or_else(dash, crate::vms::fmt_uptime),
                match r.parent.is_some() || at_rest(&r.status) {
                    true => dash(),
                    false => crate::vms::mem_cell(r.mem_used_bytes, r.mem.as_deref()),
                },
                r.image.clone().unwrap_or_else(dash),
                crate::vms::project_cell(r.project.as_deref(), home, wide),
            ];
            if wide {
                row.push(r.exec_addr.clone().unwrap_or_else(dash));
            }
            row.push(match r.published.is_empty() {
                true => dash(),
                false => r.published.join(", "),
            });
            if stale {
                row.push(match r.stale {
                    Some(Some(true)) => "yes".into(),
                    Some(Some(false)) => "no".into(),
                    _ => dash(),
                });
            }
            row
        })
        .collect();
    crate::dev::list::table(&headers, &cells)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(dir: &str, project: &str, pid: u32, services: &[&str]) -> VmEntry {
        let mut e = crate::vms::tests::entry(PathBuf::from(dir), Some(PathBuf::from(project)));
        e.pid = pid;
        e.label = format!("img-{pid}");
        e.created_secs = 100;
        e.services = services
            .iter()
            .map(|s| crate::vms::ServiceEntry {
                name: s.to_string(),
                exec_addr: format!("vsock-auto://{dir}/svc-{s}/vsock.sock:4444"),
                stale_recipe: None,
            })
            .collect();
        e
    }

    fn unit(name: &str, state: &str) -> UnitStatus {
        UnitStatus {
            name: name.into(),
            state: state.into(),
            ip: "10.0.0.5/24".into(),
            ..Default::default()
        }
    }

    fn live<'a>(e: &'a VmEntry, name: &str, kind: Kind, units: Vec<UnitStatus>) -> Live<'a> {
        Live {
            entry: e,
            name: Some(name.into()),
            kind,
            environment: None,
            units: Some(units),
            published: Vec::new(),
            mem_used: Some(1 << 30),
            fresh: None,
            transient: None,
            attention: None,
            stale_record: false,
        }
    }

    /// Rows as if every declared service had booted once.
    fn rows(live: &[Live], known: &[Known], now: u64) -> Vec<Row> {
        rows_with(live, known, now, |_| true)
    }

    fn names(rows: &[Row]) -> Vec<&str> {
        rows.iter().map(|r| r.name.as_str()).collect()
    }

    #[test]
    fn a_running_service_shows_its_vmm_memory_and_image() {
        let app = entry("/s/app", "/w/app", 10, &["runner", "db"]);
        // A live process stands in for the runner's VMM.
        let runner = UnitStatus {
            pid: Some(std::process::id()),
            mem: Some("2G".into()),
            image: Some("gitlab/gitlab-runner:v17".into()),
            ..unit("runner", "running")
        };
        let rows = rows(
            &[live(
                &app,
                "app",
                Kind::Dev,
                vec![runner, unit("db", "running")],
            )],
            &[],
            160,
        );
        let by = |n: &str| rows.iter().find(|r| r.name == n).unwrap();
        let r = by("app/runner");
        assert_eq!(r.pid, Some(std::process::id()));
        assert!(r.uptime_secs.is_some());
        assert!(r.mem_used_bytes.is_some_and(|b| b > 0));
        assert_eq!(r.mem.as_deref(), Some("2G"));
        assert_eq!(r.image.as_deref(), Some("gitlab/gitlab-runner:v17"));
        // A manager that predates these reports none: the row says nothing it cannot know.
        let db = by("app/db");
        assert_eq!(
            (db.pid, db.mem_used_bytes, &db.mem, &db.image),
            (None, None, &None, &None)
        );
    }

    #[test]
    fn rows_group_by_project_dev_first_primary_then_its_services_by_name() {
        let app = entry("/s/app", "/w/app", 10, &["web", "db"]);
        let tool = entry("/s/tool", "/w/app", 11, &[]);
        let other = entry("/s/other", "/w/other", 12, &[]);
        let stopped = Known {
            name: "zeta".into(),
            dir: "/s/zeta".into(),
            kind: Kind::Run,
            status: STOPPED,
            attention: None,
            stale_record: false,
            last: Some(entry("/s/zeta", "/w/app", 13, &["cache"])),
            project: Some("/w/app".into()),
            environment: None,
        };
        let rows = rows(
            &[
                live(&tool, "tool", Kind::Run, vec![]),
                live(&other, "other", Kind::Run, vec![]),
                live(&app, "app", Kind::Dev, vec![unit("db", "running")]),
            ],
            &[stopped],
            160,
        );
        assert_eq!(
            names(&rows),
            [
                "app",
                "app/db",
                "app/web",
                "tool",
                "zeta",
                "zeta/cache",
                "other"
            ]
        );
        let by = |n: &str| rows.iter().find(|r| r.name == n).unwrap();
        assert_eq!(by("app").uptime_secs, Some(60));
        assert_eq!(by("app/db").status, "running");
        assert_eq!(by("app/db").ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(by("app/db").state_dir, PathBuf::from("/s/app/svc-db"));
        // Declared but not reported: unknown, not stopped.
        assert_eq!(by("app/web").status, "-");
        assert_eq!(by("zeta").status, STOPPED);
        assert_eq!(by("zeta").image.as_deref(), Some("img-13"));
        assert_eq!(by("zeta/cache").status, STOPPED);
        assert_eq!(by("zeta/cache").parent.as_deref(), Some("zeta"));
    }

    /// A reported state other than `stopped` or a previous console log qualifies a service.
    /// With a stopped primary, only the log is available.
    #[test]
    fn a_service_without_a_vm_gets_no_row() {
        let app = entry("/s/app", "/w/app", 10, &["db", "lazy", "off", "old", "web"]);
        let zeta = Known {
            name: "zeta".into(),
            dir: "/s/zeta".into(),
            kind: Kind::Run,
            status: STOPPED,
            attention: None,
            stale_record: false,
            last: Some(entry("/s/zeta", "/w/app", 13, &["cache", "never"])),
            project: None,
            environment: None,
        };
        let once = [Path::new("/s/app/svc-old"), Path::new("/s/zeta/svc-cache")];
        let rows = rows_with(
            &[live(
                &app,
                "app",
                Kind::Run,
                vec![
                    unit("db", "running"),
                    unit("off", STOPPED),
                    unit("old", STOPPED),
                    unit("web", "starting"),
                ],
            )],
            &[zeta],
            0,
            |d| once.contains(&d),
        );
        assert_eq!(
            names(&rows),
            ["app", "app/db", "app/old", "app/web", "zeta", "zeta/cache"]
        );
    }

    /// A VM on its way up or down says so, and counts as running for the filters; state
    /// that never booted counts as stopped.
    #[test]
    fn transient_and_never_booted_states_are_named_and_filtered() {
        let app = entry("/s/app", "/w/app", 10, &[]);
        let mut going = live(&app, "app", Kind::Run, vec![]);
        going.transient = Some("stopping");
        // A second VM whose stop timed out: still `stopping`, as recorded, and flagged.
        let hung = entry("/s/hung", "/w/app", 11, &[]);
        let mut stuck = live(&hung, "hung", Kind::Run, vec![]);
        stuck.transient = Some("stopping");
        stuck.attention = Some("a stop timed out".into());
        let known = |name: &str, status: &'static str| Known {
            name: name.into(),
            dir: format!("/s/{name}").into(),
            kind: Kind::Dev,
            status,
            attention: None,
            stale_record: status == NEVER_BOOTED,
            last: None,
            project: None,
            environment: None,
        };
        let rows = rows(
            &[going, stuck],
            &[
                known("coming", "starting"),
                known("task-1a2b", NEVER_BOOTED),
            ],
            0,
        );
        let status = |n: &str| rows.iter().find(|r| r.name == n).unwrap().status.clone();
        assert_eq!(status("app"), "stopping");
        assert_eq!(status("coming"), "starting");
        assert_eq!(status("task-1a2b"), NEVER_BOOTED);
        let keep = |f: Filter| {
            let mut kept: Vec<String> = f.apply(rows.clone()).into_iter().map(|r| r.name).collect();
            kept.sort_unstable();
            kept
        };
        let states = |states: &[State]| Filter {
            states: states.to_vec(),
            ..Filter::default()
        };
        // Nothing here is up: on their way, these count as neither running nor stopped.
        assert!(keep(states(State::RUNNING)).is_empty());
        assert_eq!(keep(states(&[State::Stopping])), ["app", "hung"]);
        assert_eq!(keep(states(State::STOPPED)), ["task-1a2b"]);
        assert_eq!(keep(states(&[State::NeverBooted])), ["task-1a2b"]);
        assert_eq!(
            keep(states(&[State::Running, State::Starting, State::Stopping])),
            ["app", "coming", "hung"]
        );
        // `--problems` keeps what needs attention and what came from stale records.
        assert_eq!(status("hung"), "stopping");
        let problems = Filter {
            problems: true,
            ..Filter::default()
        };
        assert_eq!(keep(problems), ["hung", "task-1a2b"]);
        // Markers decorate table cells. JSON retains the status, including `never booted`.
        let table = render(&rows, None, false, false);
        assert!(table.contains("task-1a2b  dev   never booted*"), "{table}");
        assert!(table.contains("stopping!"), "{table}");
        let json = serde_json::to_string(&rows).unwrap();
        assert!(json.contains("\"status\":\"never booted\""), "{json}");
        assert_eq!(json.matches("\"attention\"").count(), 1, "{json}");
        assert_eq!(json.matches("\"stale_record\":true").count(), 1, "{json}");
        assert!(!json.contains("\"stale_record\":false"), "{json}");
    }

    #[test]
    fn booted_reads_the_console_log() {
        let dir = std::env::temp_dir().join(format!("vk-vmlist-booted-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!booted(&dir));
        std::fs::write(dir.join(crate::run::CONSOLE_LOG), "").unwrap();
        assert!(booted(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unnamed_running_vm_is_named_by_its_pid() {
        let e = entry("/s/x", "/w/x", 4242, &["db"]);
        let mut l = live(&e, "ignored", Kind::Run, vec![]);
        l.name = None;
        let rows = rows(&[l], &[], 0);
        assert_eq!(names(&rows), ["4242", "4242/db"]);
    }

    #[test]
    fn filters_keep_by_status_kind_and_service() {
        let app = entry("/s/app", "/w/app", 10, &["db", "web"]);
        let other = entry("/s/other", "/w/app", 11, &["db"]);
        // `other`'s service manager could not be asked: its service's state is unknown.
        let mut unasked = live(&other, "other", Kind::Run, vec![]);
        unasked.units = None;
        let rows = rows(
            &[
                live(
                    &app,
                    "app",
                    Kind::Run,
                    vec![unit("db", "stopped"), unit("web", "running")],
                ),
                unasked,
            ],
            &[],
            0,
        );
        assert_eq!(
            rows.iter().find(|r| r.name == "other/db").unwrap().status,
            "-"
        );
        let keep = |f: Filter| {
            f.apply(rows.clone())
                .into_iter()
                .map(|r| r.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            keep(Filter {
                states: State::RUNNING.to_vec(),
                ..Filter::default()
            }),
            ["app", "app/web", "other"]
        );
        assert_eq!(
            keep(Filter {
                states: State::STOPPED.to_vec(),
                ..Filter::default()
            }),
            ["app/db"]
        );
        // `--service` keeps those services' rows alone, any of the names given.
        assert_eq!(
            keep(Filter {
                services: vec!["web".into(), "cache".into()],
                ..Filter::default()
            }),
            ["app/web"]
        );
        // `--workspace` keeps the rows of that project, below it too with `-r`.
        let workspace = |dir: &str, below: bool| Filter {
            workspace: Some(dir.into()),
            below,
            ..Filter::default()
        };
        assert_eq!(
            keep(workspace("/w/app", false)),
            ["app", "app/db", "app/web"]
        );
        assert!(keep(workspace("/w", false)).is_empty());
        assert_eq!(keep(workspace("/w", true)).len(), 3);
        assert_eq!(
            keep(Filter {
                kind: Some(Kind::Service),
                ..Filter::default()
            }),
            ["app/db", "app/web", "other/db"]
        );
        // The service component of each VM's rows; the REF picks the VM.
        assert_eq!(
            keep(Filter {
                service: Some("db".into()),
                ..Filter::default()
            }),
            ["app/db", "other/db"]
        );
        let words = |words: &[Word]| Filter {
            words: words.to_vec(),
            ..Filter::default()
        };
        let pattern = |w: &str| Word::Pattern(crate::namematch::Pattern::from_word(w));
        assert_eq!(keep(words(&[pattern("app/web")])), ["app/web"]);
        // A VM's name keeps its services' rows too; a glob may name either.
        assert_eq!(keep(words(&[pattern("app")])), ["app", "app/db", "app/web"]);
        assert_eq!(keep(words(&[pattern("*/w*")])), ["app/web"]);
        assert!(
            keep(words(&[pattern("ap")])).is_empty(),
            "a name matches whole"
        );
        // Words are any of them; other criteria narrow what they pick.
        assert_eq!(
            keep(words(&[pattern("nope"), Word::Pid(10, None)])),
            ["app", "app/db", "app/web"]
        );
        assert_eq!(keep(words(&[Word::Pid(10, Some("db".into()))])), ["app/db"]);
        assert_eq!(
            keep(Filter {
                states: State::ACTIVE.to_vec(),
                ..words(&[pattern("app*")])
            }),
            ["app", "app/web"]
        );
        let dir = |d: &str, below: bool| Word::Dir {
            dir: d.into(),
            below,
        };
        assert_eq!(
            keep(words(&[dir("/s/app", false)])).len(),
            3,
            "its state dir"
        );
        assert_eq!(keep(words(&[dir("/w/app", false)])).len(), 3, "its project");
        assert!(keep(words(&[dir("/w", false)])).is_empty());
        assert_eq!(keep(words(&[dir("/w", true)])).len(), 3);
    }

    /// Non-UTF-8 paths retain the recipe's byte representation in JSON.
    #[test]
    fn a_path_that_is_not_utf8_serializes() {
        use std::os::unix::ffi::OsStrExt;
        let odd = PathBuf::from(std::ffi::OsStr::from_bytes(b"/w/\xff"));
        let rows = rows(
            &[],
            &[Known {
                name: "odd".into(),
                dir: odd.clone(),
                kind: Kind::Run,
                status: STOPPED,
                attention: None,
                stale_record: false,
                last: None,
                project: Some(odd),
                environment: None,
            }],
            0,
        );
        let json = serde_json::to_value(&rows).unwrap();
        let bytes = serde_json::json!({"bytes": [47, 119, 47, 255]});
        assert_eq!(json[0]["project"], bytes);
        assert_eq!(json[0]["state_dir"], bytes);
        assert_eq!(json[0]["parent"], serde_json::Value::Null);
    }

    /// The README's sample table, as the formatter lays it out.
    fn readme_rows() -> String {
        let mut shop = entry(
            "/home/me/.local/state/virtkit/dev/shop-1a2b",
            "/home/me/shop",
            41877,
            &["db", "redis"],
        );
        shop.label = "devcontainer".into();
        shop.mem = Some("16G".into());
        shop.created_secs = 100_000 - 35 * 60;
        let mut app = entry(
            "/home/me/.local/state/virtkit/run/app-9f3c",
            "/home/me/app",
            41230,
            &[],
        );
        app.label = "app/Dockerfile:dev".into();
        app.mem = Some("8G".into());
        app.created_secs = 100_000 - (2 * 3600 + 14 * 60);
        let mut scratch = entry(
            "/home/me/.local/state/virtkit/run/scratch-77aa",
            "/home/me/tmp",
            1,
            &[],
        );
        scratch.label = "alpine".into();
        let pg = (
            crate::publish::Entry {
                name: "pg".into(),
                listen: "tcp://127.0.0.1:5432".into(),
                to: "tcp://127.0.0.1:5432".into(),
                service: Some("db".into()),
                pid: 42011,
                created_secs: 0,
            },
            crate::publish::Liveness::Held,
        );
        let mut shop_live = live(
            &shop,
            "shop",
            Kind::Dev,
            vec![unit("db", "running"), unit("redis", "stopped")],
        );
        shop_live.mem_used = Some(6_335_076_761);
        shop_live.published = vec![pg];
        let mut app_live = live(&app, "app", Kind::Run, vec![]);
        app_live.mem_used = Some(1_288_490_189);
        let stopped = Known {
            name: "scratch".into(),
            dir: scratch.state_dir.clone(),
            kind: Kind::Run,
            status: STOPPED,
            attention: None,
            stale_record: false,
            last: Some(scratch.clone()),
            project: scratch.project_dir.clone(),
            environment: None,
        };
        let rows = rows(&[shop_live, app_live], &[stopped], 100_000);
        render(&rows, Some(Path::new("/home/me")), false, false)
    }

    #[test]
    fn readme_table_sample_is_what_the_formatter_emits() {
        let table = readme_rows();
        let readme = include_str!("../../README.md");
        assert!(readme.contains(&table), "README.md should hold:\n{table}");
    }

    #[test]
    fn the_table_starts_with_the_name_and_dashes_what_a_row_lacks() {
        let app = entry("/s/app", "/w/app", 10, &["db"]);
        let rows = rows(
            &[live(&app, "app", Kind::Dev, vec![unit("db", "running")])],
            &[],
            160,
        );
        let out = render(&rows, None, false, false);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("NAME    KIND"), "{out}");
        assert!(lines[1].starts_with("app     dev"), "{out}");
        assert!(lines[2].starts_with("app/db  service  running  -"), "{out}");
        assert!(
            render(&rows, None, true, true)
                .lines()
                .next()
                .unwrap()
                .contains("EXEC_ADDRESS")
        );
    }
}
